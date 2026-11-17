package detect

import (
	"unicode"
)

// NormalizeFullWidthDigits converts full-width digits and Unicode dash separators to ASCII. Interior non-ASCII Pd, Zs, Cf and Sm intersected with Dash are ignored. The returned map translates normalized byte indexes to original indexes, including an end sentinel equal to len(data).
//
// ASCII-only input is returned unchanged with an allocated identity map; input containing non-ASCII bytes uses a new buffer. U+30FC remains a legacy numeric hyphen. Other bytes are preserved.
func NormalizeFullWidthDigits(data []byte) (normalizedData []byte, positions []int) {
	// Quick check: if no multi-byte characters, return as-is.
	hasMultiByte := false
	for _, b := range data {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if b >= 0x80 {
			hasMultiByte = true
			break
		}
	}
	if !hasMultiByte {
		posMap := make([]int, normalizationMapSize(len(data)))
		for i := range posMap {
			posMap[i] = i
		}
		return data, posMap
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

// normalizeDigits uses a nil identity map when no byte can change.
func normalizeDigits(data []byte) (normalized []byte, positions []int) {
	for _, b := range data {
		if b >= 0x80 { //nolint:mnd // UTF-8 continuation and leading bytes.
			return NormalizeFullWidthDigits(data)
		}
	}
	return data, nil
}
