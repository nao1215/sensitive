package detect

import (
	"unicode"
	"unicode/utf8"
)

// NormalizeFullWidthDigits converts full-width digits and Unicode dash separators to ASCII. Interior non-ASCII Pd, Zs, Cf and Sm intersected with Dash are ignored. The returned map translates normalized byte indexes to original indexes, including an end sentinel equal to len(data).
//
// ASCII-only input is returned unchanged with an allocated identity map; input containing non-ASCII bytes uses a new buffer. U+30FC remains a legacy numeric hyphen. Other bytes are preserved.
func NormalizeFullWidthDigits(data []byte) (normalizedData []byte, positions []int) {
	// Quick check: if no multi-byte characters, return as-is.
	if firstNonASCII(data) < 0 {
		return data, identityPositions(len(data))
	}

	normalized := make([]byte, 0, len(data))
	posMap := make([]int, 0, normalizationMapSize(len(data)))

	i := 0
	for i < len(data) {
		r, size := normalizationRune(data, i)
		switch {
		case r >= 0xFF10 && r <= 0xFF19:
			// Full-width digit → half-width digit.
			posMap = append(posMap, i)
			//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
			normalized = append(normalized, byte(r-0xFEE0))
		case unicode.Is(unicode.Pd, r) || unicode.Is(unicode.Sm, r) && unicode.Is(unicode.Dash, r) || r == 0x30FC:
			// Full-width hyphen variants → ASCII hyphen.
			posMap = append(posMap, i)
			normalized = append(normalized, '-')
		case r == 0x3000: //nolint:mnd // Unicode IDEOGRAPHIC SPACE.
			posMap = append(posMap, i)
			normalized = append(normalized, ' ')
		case ignoredTokenSeparator(r) && tokenInterior(data, i, size):
			// Interior formatting runs have no semantic token bytes.
		default:
			// Copy bytes as-is.
			for k := range size {
				posMap = append(posMap, i+k)
				normalized = append(normalized, data[i+k])
			}
		}
		i += size
	}

	// Sentinel: map the end position.
	posMap = append(posMap, len(data))

	return normalized, posMap
}

// identityPositions allocates the identity map for n unchanged bytes,
// including the end sentinel.
func identityPositions(n int) []int {
	posMap := make([]int, normalizationMapSize(n))
	for i := range posMap {
		posMap[i] = i
	}
	return posMap
}

// normalizeDigits uses a nil identity map when no byte can change.
func normalizeDigits(data []byte) (normalized []byte, positions []int) {
	for _, b := range data {
		if b >= 0x80 { //nolint:mnd // UTF-8 continuation and leading bytes.
			return NormalizeFullWidthDigits(data)
		}
	}
	return data, nil
}

// foldFullWidthASCII converts the full-width forms of printable ASCII, U+FF01
// to U+FF5E, to ASCII and copies every other byte. The map translates folded
// byte indexes to original indexes and ends with the len(data) sentinel.
func foldFullWidthASCII(data []byte) (folded []byte, positions []int) {
	folded = make([]byte, 0, len(data))
	positions = make([]int, 0, normalizationMapSize(len(data)))
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r >= '！' && r <= '～' {
			positions = append(positions, i)
			folded = append(folded, byte(r-'！'+'!'))
			i += size
			continue
		}
		for k := range size {
			positions = append(positions, i+k)
			folded = append(folded, data[i+k])
		}
		i += size
	}
	return folded, append(positions, len(data))
}
