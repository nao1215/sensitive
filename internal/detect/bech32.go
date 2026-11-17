package detect

import "github.com/nao1215/embargo/internal/ascii"

// Bech32 and Bech32m (BIP-173, BIP-350) decoding for SegWit addresses.

// isBech32ConsistentCase reports whether all characters in s are the same case.
// Digits are case-neutral and do not affect the result.
func isBech32ConsistentCase(s string) bool {
	hasLower := false
	hasUpper := false
	for i := range len(s) {
		hasLower = hasLower || ascii.IsLower(s[i])
		hasUpper = hasUpper || ascii.IsUpper(s[i])
	}
	return !hasLower || !hasUpper
}

// bech32ChecksumConst is the expected polymod result for valid bech32 (BIP-173).
const bech32ChecksumConst = 1

// bech32mChecksumConst is the expected polymod result for valid bech32m (BIP-350).
const bech32mChecksumConst = 0x2bc830a3

// bech32Generator contains the polynomial generator values for bech32 checksums.
func bech32Generator() [5]int {
	return [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
}

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
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		b := chk >> 25
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := range 5 {
			if (b>>uint(i))&1 == 1 {
				chk ^= bech32Generator()[i]
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
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		ret = append(ret, int(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range []byte(hrp) {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
