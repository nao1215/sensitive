package detect

import (
	"bytes"
	"math"
	"strconv"
	"unicode/utf8"
)

// NormalizeFullWidthDigits converts U+FF10–U+FF19 digits and hyphen variants U+FF0D, U+30FC, U+2212 and U+2010–U+2015 to ASCII; U+3000 becomes a space. The returned map translates normalized byte indexes to original indexes, including an end sentinel equal to len(data).
//
// ASCII-only input is returned unchanged with an allocated identity map; input containing non-ASCII bytes uses a new buffer. U+200B, U+00A0, U+202F and U+00AD inside tokens are ignored; other bytes are preserved.
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
		case r == 0xFF0D || r == 0x30FC || r == 0x2212 || r >= 0x2010 && r <= 0x2015:
			// Full-width hyphen variants → ASCII hyphen.
			posMap = append(posMap, i)
			normalized = append(normalized, '-')
		case r == 0x3000: //nolint:mnd // Unicode IDEOGRAPHIC SPACE.
			posMap = append(posMap, i)
			normalized = append(normalized, ' ')
		case ignoredTokenSeparator(r) && tokenInterior(data, i, size):
			// Interior formatting marks have no semantic token bytes.
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
// position map returned by NormalizeFullWidthDigits; nil denotes identity.
func mapOriginalRange(posMap []int, start, end int) (origStart, origEnd int) {
	if posMap == nil {
		return start, end
	}
	origStart = posMap[start]
	origEnd = posMap[end-1] + 1
	if end < len(posMap) {
		origEnd = posMap[end]
	}
	return origStart, origEnd
}

func normalizationMapSize(length int) int {
	// Bound the sentinel addition and the int slice backing storage before arithmetic.
	const bytesPerInt = strconv.IntSize / 8
	if length > math.MaxInt/bytesPerInt-1 {
		panic("embargo: input too large")
	}
	return length + 1
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

func originalPosition(positions []int, index int) int {
	if positions == nil {
		return index
	}
	return positions[index]
}

// RemoveTokenSeparators ignores U+200B, U+00A0, U+202F and U+00AD inside
// alphanumeric tokens. The optional map includes the original end sentinel.
// Other whitespace, invalid UTF-8 and marks outside tokens remain unchanged.
func RemoveTokenSeparators(data []byte) (normalized []byte, positions []int) {
	// UTF-8 encodes all four marks with C2 or E2. Keep ordinary ASCII scans
	// allocation-free and use byte searches before decoding any rune.
	const twoByteLead, threeByteLead = 0xC2, 0xE2
	first := bytes.IndexByte(data, twoByteLead)
	if other := bytes.IndexByte(data, threeByteLead); other >= 0 && (first < 0 || other < first) {
		first = other
	}
	if first < 0 {
		return data, nil
	}
	for i := first; i < len(data); {
		r, size := normalizationRune(data, i)
		remove := ignoredTokenSeparator(r) && tokenInterior(data, i, size)
		if remove && normalized == nil {
			normalized = append(make([]byte, 0, len(data)), data[:i]...)
			positions = make([]int, i, normalizationMapSize(len(data)))
			for j := range positions {
				positions[j] = j
			}
		}
		if normalized != nil && !remove {
			normalized = append(normalized, data[i:i+size]...)
			for j := range size {
				positions = append(positions, i+j)
			}
		}
		i += size
	}
	if normalized == nil {
		return data, nil
	}
	return normalized, append(positions, len(data))
}

func ignoredTokenSeparator(r rune) bool {
	return r == 0x200B || r == 0x00A0 || r == 0x202F || r == 0x00AD
}

func tokenInterior(data []byte, i, size int) bool {
	if i == 0 || i+size == len(data) {
		return false
	}
	before, _ := utf8.DecodeLastRune(data[:i])
	after, _ := utf8.DecodeRune(data[i+size:])
	return tokenRune(before) && tokenRune(after)
}

func tokenRune(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= 0xFF10 && r <= 0xFF19 || r == '_' || r == '-' || r == '.' || r == '/' || r == '+'
}

// Consume consecutive formatting marks together, so a run is handled once.
func normalizationRune(data []byte, index int) (value rune, size int) {
	value, size = utf8.DecodeRune(data[index:])
	if !ignoredTokenSeparator(value) {
		return value, size
	}
	for index+size < len(data) {
		next, width := utf8.DecodeRune(data[index+size:])
		if !ignoredTokenSeparator(next) {
			break
		}
		size += width
	}
	return value, size
}
