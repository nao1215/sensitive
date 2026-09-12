package detector

import (
	"crypto/sha256"
)

// BTCAddressType identifies the Bitcoin address encoding format.
// Use the BTCAddress* constants for comparison with [BTCDetail.AddressType].
//
//	if detail.AddressType == detector.BTCAddressP2PKH { ... }
type BTCAddressType string

const (
	// BTCAddressP2PKH identifies Pay-to-Public-Key-Hash addresses (prefix '1').
	BTCAddressP2PKH BTCAddressType = "p2pkh"
	// BTCAddressP2SH identifies Pay-to-Script-Hash addresses (prefix '3').
	BTCAddressP2SH BTCAddressType = "p2sh"
	// BTCAddressBech32 identifies SegWit v0 addresses (prefix 'bc1q').
	BTCAddressBech32 BTCAddressType = "bech32"
	// BTCAddressBech32m identifies Taproot v1 addresses (prefix 'bc1p').
	BTCAddressBech32m BTCAddressType = "bech32m"
)

// BTCDetail holds Bitcoin address-specific detail information.
type BTCDetail struct {
	// AddressType is the encoding format of the detected address.
	// Compare with the BTCAddress* constants (e.g., [BTCAddressP2PKH],
	// [BTCAddressBech32]).
	AddressType BTCAddressType
}

// BTC detects Bitcoin addresses in text.
//
// Bitcoin uses four main address formats:
//   - P2PKH (Pay-to-Public-Key-Hash): starts with '1', 25-34 Base58Check characters
//   - P2SH (Pay-to-Script-Hash): starts with '3', 25-34 Base58Check characters
//   - Bech32 SegWit v0: starts with 'bc1q', exactly 42 characters (P2WPKH) or 62 characters (P2WSH)
//   - Bech32m Taproot v1: starts with 'bc1p', exactly 62 characters (P2TR)
//
// Detection logic:
//  1. Scan for potential address start characters ('1', '3', 'b'/'B')
//  2. For legacy addresses: extract Base58 character sequence, validate length (25-34),
//     decode Base58, verify double-SHA-256 checksum (last 4 bytes)
//  3. For bech32/bech32m: match 'bc1' prefix, extract bech32 characters,
//     validate length (42 or 62), verify polynomial checksum
//  4. Check word boundaries to avoid matching substrings of larger identifiers
//
// Confidence: 0.95 when checksum validation passes.
type BTC struct{}

// NewBTC creates a new Bitcoin address detector.
func NewBTC() *BTC {
	return &BTC{}
}

// Name returns "btc".
func (d *BTC) Name() DetectorName {
	return NameBTC
}

// Hints returns nil, causing the Scanner to always run BTC detection.
// Legacy addresses start with '1' or '3', which are single-byte sequences
// that appear in nearly all text, making them ineffective as pre-filter hints.
// The Scan method itself performs fast character-class rejection, so the cost
// of always scanning is negligible.
func (d *BTC) Hints() [][]byte {
	return nil
}

// Scan examines data for Bitcoin addresses and returns findings.
// Both legacy (Base58Check) and bech32/bech32m (SegWit/Taproot) formats
// are detected. Addresses are validated using their respective checksum
// algorithms before being reported.
func (d *BTC) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data); i++ {
		// Try bech32/bech32m first (most specific prefix).
		if matchBech32Prefix(data, i) {
			if f, end, ok := d.scanBech32(data, i); ok {
				findings = append(findings, f)
				i = end - 1
				continue
			}
		}

		// Try legacy addresses (P2PKH starts with '1', P2SH starts with '3').
		if data[i] == '1' || data[i] == '3' {
			if f, end, ok := d.scanLegacy(data, i); ok {
				findings = append(findings, f)
				i = end - 1
				continue
			}
		}
	}

	return findings
}

// matchBech32Prefix checks whether data[i:] starts with "bc1" or "BC1"
// (case-insensitive, but bech32 addresses must be fully lowercase or uppercase).
func matchBech32Prefix(data []byte, i int) bool {
	if i+3 > len(data) {
		return false
	}
	return (data[i] == 'b' || data[i] == 'B') &&
		(data[i+1] == 'c' || data[i+1] == 'C') &&
		data[i+2] == '1'
}

// scanBech32 attempts to parse a bech32/bech32m Bitcoin address starting at position i.
// Returns the Finding, end position, and success flag.
func (d *BTC) scanBech32(data []byte, i int) (Finding, int, bool) {
	// Word boundary: preceding character must not be alphanumeric or underscore.
	if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '_') {
		return Finding{}, 0, false
	}

	// Determine case (bech32 must be all-lowercase or all-uppercase after HRP).
	isUpper := data[i] == 'B'

	// Extract bech32 characters starting after "bc1".
	j := i + 3
	for j < len(data) && isBech32Char(data[j]) {
		j++
	}

	addrLen := j - i

	// Valid bech32 BTC addresses are exactly 42 (P2WPKH) or 62 (P2WSH/P2TR) chars.
	if addrLen != 42 && addrLen != 62 {
		return Finding{}, 0, false
	}

	// Word boundary: following character must not be alphanumeric or underscore.
	if j < len(data) && (isAlphaNum(data[j]) || data[j] == '_') {
		return Finding{}, 0, false
	}

	addr := string(data[i:j])

	// Verify consistent casing across the entire address including HRP.
	// BIP-173 requires the whole address to be single-case.
	if !isBech32ConsistentCase(addr) {
		return Finding{}, 0, false
	}

	// Normalize to lowercase for checksum validation.
	lowerAddr := toLowerString(addr)

	// Decode the data part (after "bc1").
	dataPart := lowerAddr[3:]
	decoded, ok := decodeBech32Chars(dataPart)
	if !ok {
		return Finding{}, 0, false
	}

	// Verify checksum and determine encoding version.
	checksumConst, valid := bech32VerifyChecksum("bc", decoded)
	if !valid {
		return Finding{}, 0, false
	}

	// Determine address type from witness version and checksum constant.
	// BIP-173: witness version 0 uses bech32.
	// BIP-350: witness versions 1-16 use bech32m.
	witnessVersion := decoded[0]
	var addrType BTCAddressType
	switch {
	case witnessVersion == 0 && checksumConst == bech32ChecksumConst:
		addrType = BTCAddressBech32
	case witnessVersion >= 1 && witnessVersion <= 16 && checksumConst == bech32mChecksumConst:
		addrType = BTCAddressBech32m
	default:
		// Invalid witness version / checksum variant combination.
		return Finding{}, 0, false
	}

	_ = isUpper // casing is already validated

	return Finding{
		DetectorName: d.Name(),
		Start:        i,
		End:          j,
		Confidence:   0.95,
		RawValue:     addr,
		Detail:       &BTCDetail{AddressType: addrType},
	}, j, true
}

// scanLegacy attempts to parse a legacy (P2PKH/P2SH) Bitcoin address starting at position i.
// Returns the Finding, end position, and success flag.
func (d *BTC) scanLegacy(data []byte, i int) (Finding, int, bool) {
	// Word boundary: preceding character must not be alphanumeric or underscore.
	// This matches the right-boundary check and prevents false positives from
	// non-Base58 characters like 0, I, O, l that precede the address.
	if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '_') {
		return Finding{}, 0, false
	}

	// Extract Base58 characters.
	j := i
	for j < len(data) && isBase58Char(data[j]) {
		j++
	}

	length := j - i
	// Legacy addresses are 25-34 characters (typically 33-34).
	if length < 25 || length > 34 {
		return Finding{}, 0, false
	}

	// Word boundary: following character must not be alphanumeric or underscore.
	if j < len(data) && (isAlphaNum(data[j]) || data[j] == '_') {
		return Finding{}, 0, false
	}

	addr := string(data[i:j])

	// Validate Base58Check encoding (double SHA-256 checksum).
	decoded, ok := base58Decode(addr)
	if !ok || len(decoded) != 25 {
		return Finding{}, 0, false
	}

	if !validateBase58Checksum(decoded) {
		return Finding{}, 0, false
	}

	// Determine address type from version byte.
	var addrType BTCAddressType
	switch decoded[0] {
	case 0x00:
		addrType = BTCAddressP2PKH
	case 0x05:
		addrType = BTCAddressP2SH
	default:
		return Finding{}, 0, false
	}

	return Finding{
		DetectorName: d.Name(),
		Start:        i,
		End:          j,
		Confidence:   0.95,
		RawValue:     addr,
		Detail:       &BTCDetail{AddressType: addrType},
	}, j, true
}

// isBase58Char reports whether b is a valid Base58 character.
// The Base58 alphabet is: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
// It excludes: 0, I, O, l (to avoid visual ambiguity).
func isBase58Char(b byte) bool {
	return (b >= '1' && b <= '9') ||
		(b >= 'A' && b <= 'H') ||
		(b >= 'J' && b <= 'N') ||
		(b >= 'P' && b <= 'Z') ||
		(b >= 'a' && b <= 'k') ||
		(b >= 'm' && b <= 'z')
}

// isBech32Char reports whether b is a valid bech32 data character (lowercase or digit).
func isBech32Char(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

// isBech32ConsistentCase reports whether all characters in s are the same case.
// Digits are case-neutral and do not affect the result.
func isBech32ConsistentCase(s string) bool {
	hasLower := false
	hasUpper := false
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
	}
	return !hasLower || !hasUpper
}

// toLowerString converts an ASCII string to lowercase.
func toLowerString(s string) string {
	buf := make([]byte, len(s))
	for i, b := range []byte(s) {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		buf[i] = b
	}
	return string(buf)
}

// --- Base58 encoding/decoding ---

// base58Decode decodes a Base58-encoded string into raw bytes.
// Returns the decoded bytes and whether the decoding was successful.
//
// The algorithm processes each character as a digit in base-58 arithmetic,
// accumulating the result into a big-endian byte slice. Leading '1' characters
// in the input map to 0x00 bytes in the output (preserving leading zeros).
func base58Decode(s string) ([]byte, bool) {
	// Build result by multiplying by 58 and adding each digit.
	result := make([]byte, 0, len(s))

	for _, c := range []byte(s) {
		idx := base58CharIndex(c)
		if idx < 0 {
			return nil, false
		}

		carry := idx
		for j := range result {
			carry += int(result[j]) * 58
			result[j] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			result = append(result, byte(carry&0xff))
			carry >>= 8
		}
	}

	// Count leading '1' chars (each represents a 0x00 byte).
	numLeadingZeros := 0
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		numLeadingZeros++
	}

	// Build final result: leading zeros + reversed accumulation.
	decoded := make([]byte, numLeadingZeros+len(result))
	// Leading zeros are already 0x00 (zero-value of byte slice).
	// Copy reversed result after the leading zeros.
	for i, j := numLeadingZeros, len(result)-1; j >= 0; i, j = i+1, j-1 {
		decoded[i] = result[j]
	}

	return decoded, true
}

// base58CharIndex returns the index of character c in the Base58 alphabet,
// or -1 if c is not a valid Base58 character.
func base58CharIndex(c byte) int {
	switch {
	case c >= '1' && c <= '9':
		return int(c - '1')
	case c >= 'A' && c <= 'H':
		return int(c-'A') + 9
	case c >= 'J' && c <= 'N':
		return int(c-'J') + 17
	case c >= 'P' && c <= 'Z':
		return int(c-'P') + 22
	case c >= 'a' && c <= 'k':
		return int(c-'a') + 33
	case c >= 'm' && c <= 'z':
		return int(c-'m') + 44
	default:
		return -1
	}
}

// validateBase58Checksum verifies the Base58Check checksum.
// The last 4 bytes of decoded must equal the first 4 bytes of
// SHA256(SHA256(payload)), where payload is decoded[:len(decoded)-4].
func validateBase58Checksum(decoded []byte) bool {
	if len(decoded) < 5 {
		return false
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])

	return h2[0] == checksum[0] &&
		h2[1] == checksum[1] &&
		h2[2] == checksum[2] &&
		h2[3] == checksum[3]
}

// --- Bech32/Bech32m checksum ---

// bech32ChecksumConst is the expected polymod result for valid bech32 (BIP-173).
const bech32ChecksumConst = 1

// bech32mChecksumConst is the expected polymod result for valid bech32m (BIP-350).
const bech32mChecksumConst = 0x2bc830a3

// bech32Generator contains the polynomial generator values for bech32 checksums.
var bech32Generator = [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// bech32Charset maps bech32 characters to their 5-bit values.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// decodeBech32Chars converts a bech32 data string to 5-bit integer values.
// Returns the values and whether all characters were valid.
func decodeBech32Chars(s string) ([]int, bool) {
	values := make([]int, len(s))
	for i, c := range []byte(s) {
		idx := bech32CharIndex(c)
		if idx < 0 {
			return nil, false
		}
		values[i] = idx
	}
	return values, true
}

// bech32CharIndex returns the 5-bit value of a bech32 character,
// or -1 if the character is not in the bech32 charset.
func bech32CharIndex(c byte) int {
	for i, ch := range []byte(bech32Charset) {
		if ch == c {
			return i
		}
	}
	return -1
}

// bech32Polymod computes the bech32 polynomial modular checksum.
func bech32Polymod(values []int) int {
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := range 5 {
			if (b>>uint(i))&1 == 1 {
				chk ^= bech32Generator[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands the human-readable part for checksum computation.
// Each character is split into high 3 bits and low 5 bits, separated by a zero.
func bech32HRPExpand(hrp string) []int {
	ret := make([]int, 0, len(hrp)*2+1)
	for _, c := range []byte(hrp) {
		ret = append(ret, int(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range []byte(hrp) {
		ret = append(ret, int(c&31))
	}
	return ret
}

// bech32VerifyChecksum verifies the bech32/bech32m checksum and returns
// which encoding version it matches. The checksumConst return value is
// bech32ChecksumConst for bech32 or bech32mChecksumConst for bech32m.
func bech32VerifyChecksum(hrp string, data []int) (int, bool) {
	values := bech32HRPExpand(hrp)
	values = append(values, data...)
	polymod := bech32Polymod(values)

	if polymod == bech32ChecksumConst {
		return bech32ChecksumConst, true
	}
	if polymod == bech32mChecksumConst {
		return bech32mChecksumConst, true
	}
	return 0, false
}
