package detect

import (
	"encoding/binary"
	"math/bits"

	"github.com/nao1215/embargo/internal/ascii"
)

// ETH implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindETH.
type ETH struct{}

// NewETH accepts uniform-case addresses and verifies EIP-55 for mixed-case addresses.
func NewETH() *ETH {
	return &ETH{}
}

// Name returns "eth".
func (d *ETH) Name() DetectorName {
	return NameETH
}

// Hints returns the pre-filter substrings for [ETH].
func (d *ETH) Hints() [][]byte {
	return [][]byte{
		[]byte("0x"),
		[]byte("0X"),
	}
}

// Scan returns matches in data using the rules documented on [ETH].
func (d *ETH) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-41; i++ {
		if data[i] != '0' || (data[i+1] != 'x' && data[i+1] != 'X') {
			continue
		}

		// Word boundary: preceding character must not be alphanumeric or underscore.
		if !ethWordStart(data, i) {
			continue
		}

		// Verify 40 hex characters follow the prefix.
		if !isHex40(data[i+2 : i+42]) {
			continue
		}

		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		end := i + 42

		// Word boundary: following character must not be alphanumeric or underscore.
		if end < len(data) && isIdentifierByte(data[end]) {
			continue
		}

		confidence, ok := ethConfidence(string(data[i+2 : end]))
		if !ok {
			continue // Invalid EIP-55 checksum, reject.
		}

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   confidence,
		})

		i = end - 1
	}

	return findings
}

// ethWordStart reports whether an address may start at i: the preceding byte is
// not an identifier byte unless an encoded separator precedes the prefix.
func ethWordStart(data []byte, i int) bool {
	return leadingBoundary(data, i, isIdentifierByte)
}

// ethConfidence scores the 40 hex digits of an address: uniform case has no
// checksum to verify, while mixed case must satisfy EIP-55 or is rejected.
func ethConfidence(hexPart string) (float64, bool) {
	var confidence float64

	switch hexCaseType(hexPart) {
	case hexCaseUniform:
		// All lowercase or all uppercase — valid address, no checksum to verify.
		confidence = 0.80
	case hexCaseMixed:
		// Mixed case — must validate EIP-55 checksum.
		if !validateEIP55(hexPart) {
			return 0, false
		}
		confidence = 0.95
	}
	return confidence, true
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
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(b) < 40 {
		return false
	}
	for i := range 40 {
		if !ascii.IsHexDigit(b[i]) {
			return false
		}
	}
	return true
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
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(hexAddr) != 40 {
		return false
	}

	// Compute lowercase version for hashing.
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
		if ascii.IsDigit(c) {
			continue // Digits are case-insensitive.
		}

		if !eip55LetterMatches(c, eip55Nibble(hash[i/2], i)) {
			return false
		}
	}
	return true
}

// eip55Nibble selects the hash nibble for hex position i: the high nibble for
// even positions and the low nibble for odd positions.
func eip55Nibble(hashByte byte, i int) byte {
	// Get the corresponding hash nibble.
	if i%2 == 0 {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return hashByte >> 4
	}
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	return hashByte & 0x0f
}

// eip55LetterMatches reports whether hex letter c has the case its nibble
// requires: uppercase for a nibble of 8 or more, lowercase otherwise.
func eip55LetterMatches(c, nibble byte) bool {
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if nibble >= 8 {
		// Should be uppercase.
		return c < 'a' || c > 'f'
	}
	// Should be lowercase.
	return c < 'A' || c > 'F'
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
	keccakRCValues, keccakPiLaneValues, keccakRotationValues := keccakRC(), keccakPiLane(), keccakRotation()
	for round := range 24 {
		// θ (theta): column parity mixing.
		var bc [5]uint64
		for i := range 5 {
			bc[i] = state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]
		}
		for i := range 5 {
			//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
			t := bc[(i+4)%5] ^ bits.RotateLeft64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				state[i+j] ^= t
			}
		}

		// ρ (rho) and π (pi): lane rotation and permutation (combined).
		t := state[1]
		for i := range 24 {
			j := keccakPiLaneValues[i]
			bc[0] = state[j]
			state[j] = bits.RotateLeft64(t, keccakRotationValues[i])
			t = bc[0]
		}

		// χ (chi): nonlinear row mixing.
		for j := 0; j < 25; j += 5 {
			var row [5]uint64
			copy(row[:], state[j:j+5])
			for i := range 5 {
				//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
				state[j+i] = row[i] ^ (^row[(i+1)%5] & row[(i+2)%5])
			}
		}

		// ι (iota): round constant addition.
		state[0] ^= keccakRCValues[round]
	}
}

// keccakRC contains the 24 round constants for Keccak-f[1600].
func keccakRC() [24]uint64 {
	return [24]uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}
}

// keccakPiLane stores the source lane indices for the combined ρπ step.
// keccakPiLaneValues[i] gives the source index for iteration i.
func keccakPiLane() [24]int {
	return [24]int{
		10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
		15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
	}
}

// keccakRotation stores the rotation amounts for the combined ρπ step.
func keccakRotation() [24]int {
	return [24]int{
		1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
		27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
	}
}
