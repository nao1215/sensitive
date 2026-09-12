package detector

import (
	"encoding/binary"
	"math/bits"
)

// ETHDetail holds Ethereum address-specific detail information.
type ETHDetail struct {
	// EIP55 indicates whether the address passed EIP-55 mixed-case checksum validation.
	// True means the address uses correct EIP-55 encoding; false means the address
	// was all-lowercase or all-uppercase (valid but not checksummed).
	EIP55 bool
}

// ETH detects Ethereum addresses in text.
//
// Ethereum addresses are 42 characters long: a '0x' prefix followed by 40
// hexadecimal characters representing a 20-byte account address.
//
// Detection logic:
//  1. Scan for '0x' or '0X' prefix
//  2. Verify the next 40 characters are valid hexadecimal digits
//  3. Check word boundaries (not part of a larger identifier)
//  4. If the address uses mixed case, validate the EIP-55 checksum
//     using Keccak-256 (the pre-FIPS-202 hash used by Ethereum)
//
// Confidence scoring:
//   - 0.80: all-lowercase or all-uppercase hex (valid but no checksum to verify)
//   - 0.95: mixed-case with valid EIP-55 checksum
//
// Mixed-case addresses that fail EIP-55 validation are rejected.
type ETH struct{}

// NewETH creates a new Ethereum address detector.
func NewETH() *ETH {
	return &ETH{}
}

// Name returns "eth".
func (d *ETH) Name() DetectorName {
	return NameETH
}

// Hints returns byte sequences for pre-filtering.
// Ethereum addresses always start with "0x" or "0X", providing
// effective hints for the Scanner's pre-filter stage.
func (d *ETH) Hints() [][]byte {
	return [][]byte{
		[]byte("0x"),
		[]byte("0X"),
	}
}

// Scan examines data for Ethereum addresses and returns findings.
// Both all-lowercase and EIP-55 checksummed addresses are detected.
func (d *ETH) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-41; i++ {
		if data[i] != '0' || (data[i+1] != 'x' && data[i+1] != 'X') {
			continue
		}

		// Word boundary: preceding character must not be alphanumeric or underscore.
		if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '_') {
			continue
		}

		// Verify 40 hex characters follow the prefix.
		if !isHex40(data[i+2 : i+42]) {
			continue
		}

		end := i + 42

		// Word boundary: following character must not be alphanumeric or underscore.
		if end < len(data) && (isAlphaNum(data[end]) || data[end] == '_') {
			continue
		}

		hexPart := string(data[i+2 : end])
		caseType := hexCaseType(hexPart)

		var eip55Valid bool
		var confidence float64

		switch caseType {
		case hexCaseUniform:
			// All lowercase or all uppercase — valid address, no checksum to verify.
			confidence = 0.80
			eip55Valid = false
		case hexCaseMixed:
			// Mixed case — must validate EIP-55 checksum.
			if !validateEIP55(hexPart) {
				continue // Invalid EIP-55 checksum, reject.
			}
			confidence = 0.95
			eip55Valid = true
		}

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   confidence,
			RawValue:     string(data[i:end]),
			Detail:       &ETHDetail{EIP55: eip55Valid},
		})

		i = end - 1
	}

	return findings
}

// hexCaseClass represents the case pattern of a hex string.
type hexCaseClass int

const (
	// hexCaseUniform means all hex letters are the same case (or digits only).
	hexCaseUniform hexCaseClass = iota
	// hexCaseMixed means hex letters include both uppercase and lowercase.
	hexCaseMixed
)

// isHex40 reports whether the 40-byte slice contains only hexadecimal characters.
func isHex40(b []byte) bool {
	if len(b) < 40 {
		return false
	}
	for i := range 40 {
		if !isHexChar(b[i]) {
			return false
		}
	}
	return true
}

// isHexChar reports whether b is a valid hexadecimal character (0-9, a-f, A-F).
func isHexChar(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// hexCaseType determines whether a hex string contains mixed case letters.
func hexCaseType(s string) hexCaseClass {
	hasLower := false
	hasUpper := false
	for i := range len(s) {
		if s[i] >= 'a' && s[i] <= 'f' {
			hasLower = true
		}
		if s[i] >= 'A' && s[i] <= 'F' {
			hasUpper = true
		}
	}
	if hasLower && hasUpper {
		return hexCaseMixed
	}
	return hexCaseUniform
}

// validateEIP55 validates the EIP-55 mixed-case checksum of an Ethereum address.
// The input should be the 40-character hex string without the '0x' prefix.
//
// EIP-55 algorithm:
//  1. Hash the lowercase hex representation with Keccak-256
//  2. For each hex letter in the address:
//     - If the corresponding hash nibble >= 8, the letter should be uppercase
//     - If the corresponding hash nibble < 8, the letter should be lowercase
//  3. Digits are unaffected by the checksum
func validateEIP55(hexAddr string) bool {
	if len(hexAddr) != 40 {
		return false
	}

	// Compute lowercase version for hashing.
	lower := make([]byte, 40)
	for i := range 40 {
		b := hexAddr[i]
		if b >= 'A' && b <= 'F' {
			b += 'a' - 'A'
		}
		lower[i] = b
	}

	hash := keccak256Sum(lower)

	// Check each hex letter against the hash nibble.
	for i := range 40 {
		c := hexAddr[i]
		if c >= '0' && c <= '9' {
			continue // Digits are case-insensitive.
		}

		// Get the corresponding hash nibble.
		hashByte := hash[i/2]
		var nibble byte
		if i%2 == 0 {
			nibble = hashByte >> 4
		} else {
			nibble = hashByte & 0x0f
		}

		if nibble >= 8 {
			// Should be uppercase.
			if c >= 'a' && c <= 'f' {
				return false
			}
		} else {
			// Should be lowercase.
			if c >= 'A' && c <= 'F' {
				return false
			}
		}
	}
	return true
}

// --- Keccak-256 implementation ---
//
// Keccak-256 is the pre-FIPS-202 version of SHA-3 used by Ethereum.
// It differs from SHA3-256 only in the padding domain separation byte:
// Keccak uses 0x01, while SHA3-256 uses 0x06.
//
// The Go standard library's crypto/sha3 package provides only FIPS-202
// SHA-3 functions (not legacy Keccak), so we implement Keccak-256 here
// to maintain the zero-external-dependency guarantee.
//
// Reference: https://keccak.team/keccak_specs_summary.html

// keccak256Sum computes the Keccak-256 hash of data.
// Parameters: rate=136 bytes (1088 bits), capacity=64 bytes (512 bits),
// output=32 bytes (256 bits), padding delimiter=0x01.
func keccak256Sum(data []byte) [32]byte {
	var state [25]uint64
	const rate = 136 // bytes

	// Absorb: process complete rate-sized blocks.
	offset := 0
	for offset+rate <= len(data) {
		for i := range rate / 8 {
			state[i] ^= binary.LittleEndian.Uint64(data[offset+i*8 : offset+i*8+8])
		}
		keccakF1600(&state)
		offset += rate
	}

	// Pad the final block. Keccak padding: data || 0x01 || 0x00... || 0x80.
	var lastBlock [rate]byte
	remaining := len(data) - offset
	copy(lastBlock[:], data[offset:offset+remaining])
	lastBlock[remaining] = 0x01 // Keccak domain separation (NOT SHA-3's 0x06).
	lastBlock[rate-1] |= 0x80   // Multi-rate padding final bit.

	for i := range rate / 8 {
		state[i] ^= binary.LittleEndian.Uint64(lastBlock[i*8 : i*8+8])
	}
	keccakF1600(&state)

	// Squeeze: extract 32 bytes of output (within a single rate block).
	var out [32]byte
	for i := range 4 {
		binary.LittleEndian.PutUint64(out[i*8:], state[i])
	}
	return out
}

// keccakF1600 applies the Keccak-f[1600] permutation (24 rounds) to the state.
// The state is a 5x5 array of 64-bit lanes stored in row-major order:
// state[x + 5*y] where x, y in {0..4}.
func keccakF1600(state *[25]uint64) {
	for round := range 24 {
		// θ (theta): column parity mixing.
		var bc [5]uint64
		for i := range 5 {
			bc[i] = state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]
		}
		for i := range 5 {
			t := bc[(i+4)%5] ^ bits.RotateLeft64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				state[i+j] ^= t
			}
		}

		// ρ (rho) and π (pi): lane rotation and permutation (combined).
		t := state[1]
		for i := range 24 {
			j := keccakPiLane[i]
			bc[0] = state[j]
			state[j] = bits.RotateLeft64(t, keccakRotation[i])
			t = bc[0]
		}

		// χ (chi): nonlinear row mixing.
		for j := 0; j < 25; j += 5 {
			var row [5]uint64
			copy(row[:], state[j:j+5])
			for i := range 5 {
				state[j+i] = row[i] ^ (^row[(i+1)%5] & row[(i+2)%5])
			}
		}

		// ι (iota): round constant addition.
		state[0] ^= keccakRC[round]
	}
}

// keccakRC contains the 24 round constants for Keccak-f[1600].
var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// keccakPiLane stores the source lane indices for the combined ρπ step.
// keccakPiLane[i] gives the source index for iteration i.
var keccakPiLane = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

// keccakRotation stores the rotation amounts for the combined ρπ step.
var keccakRotation = [24]int{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}
