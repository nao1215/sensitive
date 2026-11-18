package embargotest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func representations(canary []byte) [][]byte {
	// A string has no JSON marshal failures. Use both HTML and ASCII escaping.
	//nolint:errchkjson // Keep marshal errors explicit under errcheck if serialized types evolve.
	encoded, err := json.Marshal(string(canary))
	if err != nil {
		return [][]byte{canary}
	}
	needles := [][]byte{
		append([]byte(nil), canary...),
		[]byte(hex.EncodeToString(canary)),
		[]byte(strings.ToUpper(hex.EncodeToString(canary))),
		encoded[1 : len(encoded)-1],
		[]byte(fmt.Sprintf("%v", canary)),
		[]byte(strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", canary), "[]byte{"), "}")),
		[]byte(new(big.Int).SetBytes(canary).String()),
	}
	// Go quoting with and without escaping non-ASCII, and JSON written by an
	// Encoder with SetEscapeHTML(false).
	for _, quoted := range []string{strconv.QuoteToASCII(string(canary)), strconv.Quote(string(canary))} {
		needles = append(needles, []byte(quoted[1:len(quoted)-1]))
	}
	var plain bytes.Buffer
	encoder := json.NewEncoder(&plain)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(string(canary)); err == nil {
		unescaped := bytes.TrimSuffix(plain.Bytes(), []byte("\n"))
		needles = append(needles, unescaped[1:len(unescaped)-1])
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		needles = append(needles, []byte(encoding.EncodeToString(canary)))
		// Drop symbols sharing bits with the unknown prefix or suffix. The retained
		// interior includes only canary bits and works at every three-byte alignment.
		const inputBits, symbolBits, alignments = 8, 6, 3
		for shift := range alignments {
			padded := append(make([]byte, shift), canary...)
			encoded := encoding.EncodeToString(padded)
			first := (shift*inputBits + symbolBits - 1) / symbolBits
			last := len(padded) * inputBits / symbolBits
			if last > first {
				needles = append(needles, []byte(encoded[first:last]))
			}
		}
	}
	return needles
}

// containsCanary reports any representation in data, also after one layer of
// JSON backslash-u escapes and one layer of percent escapes are decoded, so
// output that escapes the canary character by character, as url.QueryEscape
// and an ASCII-only JSON encoder do, is still a leak.
func containsCanary(data []byte, needles [][]byte) bool {
	for _, view := range decodedViews(data) {
		for _, needle := range needles {
			if len(needle) > 0 && bytes.Contains(view, needle) {
				return true
			}
		}
	}
	return false
}

// decodedViews returns data, its backslash-u decoding, and that decoding with
// percent escapes decoded once with plus kept and once with plus as a space.
// Malformed escapes stay literal. A view that would equal the previous one is
// left out.
func decodedViews(data []byte) [][]byte {
	views := [][]byte{data}
	unescaped := data
	if bytes.Contains(data, []byte{'\\', 'u'}) {
		unescaped = decodeUnicodeEscapes(data)
		views = append(views, unescaped)
	}
	if bytes.IndexByte(unescaped, '%') >= 0 || bytes.IndexByte(unescaped, '+') >= 0 {
		views = append(views, decodePercent(unescaped, false), decodePercent(unescaped, true))
	}
	return views
}

// decodeUnicodeEscapes decodes every backslash, u and four hex digits as
// encoding/json does, joining surrogate pairs; other bytes are copied.
func decodeUnicodeEscapes(data []byte) []byte {
	decoded := make([]byte, 0, len(data))
	for i := 0; i < len(data); {
		r, width := unicodeEscape(data, i)
		if width == 0 {
			decoded = append(decoded, data[i])
			i++
			continue
		}
		if utf16.IsSurrogate(r) {
			if low, next := unicodeEscape(data, i+width); next > 0 {
				if pair := utf16.DecodeRune(r, low); pair != utf8.RuneError {
					r, width = pair, width+next
				}
			}
		}
		decoded = utf8.AppendRune(decoded, r)
		i += width
	}
	return decoded
}

// unicodeEscape returns the code unit escaped at data[i:] and the escape
// length, or zero when no escape starts there.
func unicodeEscape(data []byte, i int) (unit rune, width int) {
	const escapeLength = len(`\u0000`)
	if i+escapeLength > len(data) || data[i] != '\\' || data[i+1] != 'u' {
		return 0, 0
	}
	value, err := strconv.ParseUint(string(data[i+2:i+escapeLength]), 16, 16)
	if err != nil {
		return 0, 0
	}
	return rune(value), escapeLength
}

// decodePercent decodes each valid %HH escape and, when plusIsSpace, reads +
// as a space the way url.QueryUnescape does.
func decodePercent(data []byte, plusIsSpace bool) []byte {
	decoded := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		if data[i] == '+' && plusIsSpace {
			decoded = append(decoded, ' ')
			continue
		}
		if data[i] == '%' && i+2 < len(data) {
			if value, err := strconv.ParseUint(string(data[i+1:i+3]), 16, 8); err == nil {
				decoded = append(decoded, byte(value))
				i += 2
				continue
			}
		}
		decoded = append(decoded, data[i])
	}
	return decoded
}

type fragmentOption int

// WithCanaryFragments also checks every contiguous raw canary fragment of at
// least minBytes bytes. The minimum must be 16 through the final canary length.
// This opt-in policy catches long partial values and pieces on separate lines
// or sinks; it does not reconstruct smaller pieces or transform fragments.
// Choose a distinctive fake canary: matching a common fragment can reject
// unrelated output. The default checks only whole-value representations.
func WithCanaryFragments(minBytes int) Option { return fragmentOption(minBytes) }

func (o fragmentOption) apply(r *Recorder) bool {
	const smallestFragment = 16
	const largestCanary = 1024
	if int(o) < smallestFragment || int(o) > largestCanary {
		return false
	}
	r.minFragment = int(o)
	return true
}

func (r *Recorder) configureNeedles() {
	r.needles = representations(r.canary)
	if r.minFragment > len(r.canary) {
		r.failed = true
		return
	}
	if r.minFragment == 0 {
		return
	}
	// A longer raw fragment necessarily contains a minimum-length window.
	// The canary already belongs to the policy and remains immutable.
	seen := make(map[string]bool)
	for start := 0; start+r.minFragment <= len(r.canary); start++ {
		fragment := r.canary[start : start+r.minFragment]
		if !seen[string(fragment)] {
			seen[string(fragment)] = true
			r.needles = append(r.needles, fragment)
		}
	}
}
