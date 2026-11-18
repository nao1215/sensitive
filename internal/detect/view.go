package detect

import (
	"bytes"
	"encoding/binary"
	"math"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/nao1215/embargo/internal/ascii"
)

// View is the text every built-in detector scans: one layer of ASCII
// backslash-u escapes and then one layer of percent escapes decoded, and
// Unicode separators inside tokens removed. Positions maps each
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
	if plainASCII(raw) {
		// No layer applies: escapes need a backslash or '%', separators are non-ASCII.
		return View{Raw: raw, Data: raw}
	}
	unescaped, unicodeMap := decodeUnicodeEscapes(raw)
	decoded, percent := decodePercent(unescaped)
	data, token := removeTokenSeparators(decoded)
	return View{Raw: raw, Data: data, Positions: composePositions(composePositions(token, percent), unicodeMap)}
}

// plainASCII reports whether data is ASCII without a backslash or '%'.
func plainASCII(data []byte) bool {
	for _, b := range data {
		if b >= utf8.RuneSelf || b == '\\' || b == '%' {
			return false
		}
	}
	return true
}

// decodeUnicodeEscapes decodes one layer of the JSON and Go escape of a
// backslash, u and four hex digits when the code point is ASCII, so a value
// spelled with escaped punctuation reads as the value. Non-ASCII escapes stay
// literal because decoding them would let names and prose in other scripts
// reach the detectors as new text; an escaped backslash and malformed escapes
// stay literal too. A nil map denotes identity; otherwise it includes the end
// sentinel.
func decodeUnicodeEscapes(data []byte) (decoded []byte, positions []int) {
	if !bytes.Contains(data, []byte{'\\', 'u'}) {
		return data, nil
	}
	for i := 0; i < len(data); {
		c, ok := asciiUnicodeEscape(data, i)
		if !ok {
			width := literalWidth(data, i)
			if decoded != nil {
				decoded = append(decoded, data[i:i+width]...)
				for j := range width {
					positions = append(positions, i+j)
				}
			}
			i += width
			continue
		}
		if decoded == nil {
			// The escape removes five bytes, so len(data) also holds the sentinel.
			decoded, positions = identityPrefix(data, i, len(data))
		}
		decoded = append(decoded, c)
		positions = append(positions, i)
		i += len(`\u0000`)
	}
	if decoded == nil {
		return data, nil
	}
	positions = append(positions, len(data))
	return decoded, positions
}

// literalWidth is two for an escaped backslash, whose next byte is not the
// start of an escape, and one for any other byte.
func literalWidth(data []byte, i int) int {
	if data[i] == '\\' && i+1 < len(data) && data[i+1] == '\\' {
		return len(`\\`)
	}
	return 1
}

// asciiUnicodeEscape reports the ASCII byte escaped at data[i:i+6].
func asciiUnicodeEscape(data []byte, i int) (byte, bool) {
	const escapeLength = len(`\u0000`)
	if i+escapeLength > len(data) || data[i] != '\\' || data[i+1] != 'u' || data[i+2] != '0' || data[i+3] != '0' {
		return 0, false
	}
	hi, ok := ascii.DecodeHex(data[i+4])
	lo, ok2 := ascii.DecodeHex(data[i+5])
	const asciiHighNibble = 7
	if !ok || !ok2 || hi > asciiHighNibble {
		return 0, false
	}
	return hi<<4 | lo, true
}

// Original maps a Data index to its Raw index.
func (v View) Original(index int) int { return originalPosition(v.Positions, index) }

// viewScanner is implemented by detectors that need the raw bytes as well as
// the normalised text; they return findings in raw offsets.
type viewScanner interface {
	scanView(v View) []Finding
}

// appendScanner is a detector that appends its findings to a caller's slice,
// so a scan that reuses one buffer allocates nothing per detector.
type appendScanner interface {
	appendScan(dst []Finding, data []byte) []Finding
}

// AppendScanView is ScanView that appends to dst, reusing its storage when d
// can append.
func AppendScanView(dst []Finding, d Detector, v View) []Finding {
	as, ok := d.(appendScanner)
	if _, raw := d.(viewScanner); raw || !ok {
		return append(dst, ScanView(d, v)...)
	}
	start := len(dst)
	dst = as.appendScan(dst, v.Data)
	if v.Positions != nil {
		for i := start; i < len(dst); i++ {
			dst[i].Start, dst[i].End = v.Positions[dst[i].Start], v.Positions[dst[i].End]
		}
	}
	return dst
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
			// The first escape removes two bytes, leaving room for the sentinel
			// within len(data) and avoiding overflow from adding capacity.
			decoded, positions = identityPrefix(data, i, len(data))
		}
		decoded = append(decoded, hi<<4|lo)
		positions = append(positions, i)
		i += 3
		i, decoded, positions = copyPercentLiteral(data, i, decoded, positions)
		i--
	}
	if decoded == nil {
		return data, nil
	}
	positions = append(positions, len(data))
	return decoded, positions
}

// copyPercentLiteral copies bytes from i up to the next valid %HH escape,
// keeping literal plus and malformed escapes, and returns where it stopped.
func copyPercentLiteral(data []byte, i int, decoded []byte, positions []int) (next int, decodedOut []byte, positionsOut []int) {
	for i < len(data) {
		if data[i] == '%' && i+2 < len(data) {
			_, ok := ascii.DecodeHex(data[i+1])
			_, ok2 := ascii.DecodeHex(data[i+2])
			if ok && ok2 {
				break
			}
		}
		decoded = append(decoded, data[i])
		positions = append(positions, i)
		i++
	}
	return i, decoded, positions
}

// identityPrefix starts a rewritten view whose first n bytes are unchanged,
// with an identity map of capacity positionCap for the remaining offsets.
func identityPrefix(data []byte, n, positionCap int) (rewritten []byte, positions []int) {
	rewritten = append(make([]byte, 0, len(data)), data[:n]...)
	positions = make([]int, n, positionCap)
	for j := range positions {
		positions[j] = j
	}
	return rewritten, positions
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
	first := firstNonASCII(data)
	if first < 0 {
		return data, nil
	}
	for i := first; i < len(data); {
		r, size := normalizationRune(data, i)
		remove := ignoredTokenSeparator(r) && tokenInterior(data, i, size)
		if remove && normalized == nil {
			normalized, positions = identityPrefix(data, i, normalizationMapSize(len(data)))
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

// firstNonASCII returns the index of the first non-ASCII byte, or -1 when
// data is pure ASCII and needs no Unicode normalization.
func firstNonASCII(data []byte) int {
	// A word has a non-ASCII byte when any high bit is set; four words are
	// tested together, then single words, then the remaining bytes.
	const highBits = 0x8080808080808080
	i := 0
	for ; i+32 <= len(data); i += 32 {
		block := data[i : i+32 : i+32]
		if (binary.LittleEndian.Uint64(block)|binary.LittleEndian.Uint64(block[8:])|binary.LittleEndian.Uint64(block[16:])|binary.LittleEndian.Uint64(block[24:]))&highBits != 0 {
			break
		}
	}
	for ; i+8 <= len(data); i += 8 {
		if binary.LittleEndian.Uint64(data[i:])&highBits != 0 {
			break
		}
	}
	for ; i < len(data); i++ {
		if data[i] >= utf8.RuneSelf {
			return i
		}
	}
	return -1
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
