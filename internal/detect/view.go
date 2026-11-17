package detect

import (
	"bytes"
	"math"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/nao1215/embargo/internal/ascii"
)

// View is the text every built-in detector scans: one layer of percent escapes
// decoded and Unicode separators inside tokens removed. Positions maps each
// Data byte index to its Raw index and ends with the len(Raw) sentinel; nil
// means Data and Raw are the same bytes. This file owns the view and every
// offset map; detectors that normalise further compose their map with it.
type View struct {
	// Raw is the caller's original input.
	Raw []byte
	// Data is the normalised text.
	Data []byte
	// Positions maps Data indexes to Raw indexes; nil is identity.
	Positions []int
}

// NewView builds the shared normalised view of raw.
func NewView(raw []byte) View {
	decoded, percent := decodePercent(raw)
	data, token := removeTokenSeparators(decoded)
	return View{Raw: raw, Data: data, Positions: composePositions(token, percent)}
}

// Original maps a Data index to its Raw index.
func (v View) Original(index int) int { return originalPosition(v.Positions, index) }

// viewScanner is implemented by detectors that need the raw bytes as well as
// the normalised text; they return findings in raw offsets.
type viewScanner interface {
	scanView(v View) []Finding
}

// ScanView runs d on v and returns findings in Raw offsets. Detectors scan
// v.Data unless they implement viewScanner.
func ScanView(d Detector, v View) []Finding {
	if vs, ok := d.(viewScanner); ok {
		return vs.scanView(v)
	}
	findings := d.Scan(v.Data)
	if v.Positions != nil {
		for i := range findings {
			findings[i].Start, findings[i].End = v.Positions[findings[i].Start], v.Positions[findings[i].End]
		}
	}
	return findings
}

// decodePercent decodes one layer of valid %HH escapes, preserving '+' and invalid
// escapes. A nil map denotes identity; otherwise it includes the end sentinel.
func decodePercent(data []byte) (decoded []byte, positions []int) {
	first := bytes.IndexByte(data, '%')
	if first < 0 {
		return data, nil
	}
	for i := first; i+2 < len(data); i++ {
		if data[i] != '%' {
			continue
		}
		hi, ok := ascii.DecodeHex(data[i+1])
		lo, ok2 := ascii.DecodeHex(data[i+2])
		if !ok || !ok2 {
			continue
		}
		if decoded == nil {
			decoded = make([]byte, 0, len(data))
			decoded = append(decoded, data[:i]...)
			// The first escape removes two bytes, leaving room for the sentinel
			// within len(data) and avoiding overflow from adding capacity.
			positions = make([]int, i, len(data))
			for j := range positions {
				positions[j] = j
			}
		}
		decoded = append(decoded, hi<<4|lo)
		positions = append(positions, i)
		i += 3
		for i < len(data) {
			if data[i] == '%' && i+2 < len(data) {
				_, ok = ascii.DecodeHex(data[i+1])
				_, ok2 = ascii.DecodeHex(data[i+2])
				if ok && ok2 {
					break
				}
			}
			decoded = append(decoded, data[i])
			positions = append(positions, i)
			i++
		}
		i--
	}
	if decoded == nil {
		return data, nil
	}
	positions = append(positions, len(data))
	return decoded, positions
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

func originalPosition(positions []int, index int) int {
	if positions == nil {
		return index
	}
	return positions[index]
}

// removeTokenSeparators ignores non-ASCII Unicode Pd, Zs, Cf and Sm/Dash inside
// alphanumeric tokens. The optional map includes the original end sentinel.
// Other whitespace, invalid UTF-8 and marks outside tokens remain unchanged.
func removeTokenSeparators(data []byte) (normalized []byte, positions []int) {
	// Keep ordinary ASCII scans allocation-free, including delimiters.
	first := -1
	for i, b := range data {
		if b >= utf8.RuneSelf {
			first = i
			break
		}
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
	return r > unicode.MaxASCII && (unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zs, r) || unicode.Is(unicode.Pd, r) || unicode.Is(unicode.Sm, r) && unicode.Is(unicode.Dash, r))
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
	return ascii.IsAlphaNumRune(r) || r >= 0xFF10 && r <= 0xFF19 || r == '_' || r == '-' || r == '.' || r == '/' || r == '+'
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

// composePositions maps child-view boundaries through a parent view in place.
// Nil is the identity view. Non-nil maps include the exclusive end sentinel;
// child entries must be valid indexes in parent. The returned map may alias either input.
func composePositions(child, parent []int) []int {
	if child == nil {
		return parent
	}
	if parent != nil {
		for i, at := range child {
			child[i] = parent[at]
		}
	}
	return child
}
