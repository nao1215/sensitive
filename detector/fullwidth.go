package detector

import "unicode/utf8"

// NormalizeFullWidthDigits converts full-width digits (U+FF10 '０' through
// U+FF19 '９') and full-width hyphens (U+FF0D '－', U+30FC 'ー', U+2010 '‐')
// to their half-width ASCII equivalents.
//
// It returns the normalized byte slice and a position map that maps each byte
// index in the normalized output back to the corresponding byte index in the
// original input. This allows Finding positions to be translated back to the
// original text coordinates.
//
// If the input contains no full-width characters, the returned normalized slice
// shares the same content as the input (no allocation), and the position map is
// an identity mapping.
func NormalizeFullWidthDigits(data []byte) ([]byte, []int) {
	// Quick check: if no multi-byte characters, return as-is.
	hasMultiByte := false
	for _, b := range data {
		if b >= 0x80 {
			hasMultiByte = true
			break
		}
	}
	if !hasMultiByte {
		posMap := make([]int, len(data)+1)
		for i := range posMap {
			posMap[i] = i
		}
		return data, posMap
	}

	normalized := make([]byte, 0, len(data))
	posMap := make([]int, 0, len(data)+1)

	i := 0
	for i < len(data) {
		r, size := utf8.DecodeRune(data[i:])
		switch {
		case r >= 0xFF10 && r <= 0xFF19:
			// Full-width digit → half-width digit.
			posMap = append(posMap, i)
			normalized = append(normalized, byte(r-0xFEE0))
		case r == 0xFF0D || r == 0x30FC || r == 0x2010:
			// Full-width hyphen variants → ASCII hyphen.
			posMap = append(posMap, i)
			normalized = append(normalized, '-')
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

// mapOriginalRange converts a normalized byte range [start, end) back to the
// corresponding byte range in the original (pre-normalization) data using the
// position map returned by NormalizeFullWidthDigits.
func mapOriginalRange(posMap []int, start, end int) (origStart, origEnd int) {
	origStart = posMap[start]
	origEnd = posMap[end-1] + 1
	if end < len(posMap) {
		origEnd = posMap[end]
	}
	return origStart, origEnd
}
