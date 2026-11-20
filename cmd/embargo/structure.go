package main

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/nao1215/embargo"
)

// structure follows what one line cannot show: the key of a value written on
// a later line of pretty-printed JSON, the lines of a YAML block under a key,
// and the custom labels of a CEF event. It adds findings for values whose key
// decides that they are sensitive, as MaskJSON's key rule does for a JSON
// line, and leaves every other value to the line's own scan.
type structure struct {
	scanner   *embargo.Scanner
	sensitive map[string]bool
	json      jsonDocument
	yaml      yamlBlock
}

// maxProbedKeys bounds the keys whose sensitivity is remembered.
const maxProbedKeys = 1024

// keyConfidence is the confidence of a value masked for its key.
const keyConfidence = 1

func newStructure(scanner *embargo.Scanner) *structure {
	return &structure{scanner: scanner, sensitive: make(map[string]bool)}
}

// open reports whether a JSON document or a YAML block continues past the
// last line, so the next line is part of it and not a JSON line of its own.
func (s *structure) open() bool { return s.json.depth() > 0 || s.yaml.open }

// findings returns the findings that the structures around body add.
func (s *structure) findings(body []byte) []embargo.Finding {
	var found []embargo.Finding
	inJSON := s.json.depth() > 0
	found = s.json.line(s, body, found)
	if !inJSON && s.json.depth() == 0 {
		// A JSON member line such as "token": would read as a YAML key.
		found = s.yaml.line(s, body, found)
	}
	return cefFindings(s, body, found)
}

// keySensitive reports whether MaskJSON masks a clean value under key, which
// is the sensitive key rule, or a key-hinted detector such as cvv, for a
// value that needs its key.
func (s *structure) keySensitive(key string) bool {
	if sensitive, ok := s.sensitive[key]; ok {
		return sensitive
	}
	// A map of strings always encodes.
	encoded, _ := json.Marshal(map[string]string{key: "x"}) //nolint:errcheck // A string map has no unsupported value.
	masked, err := s.scanner.MaskJSON(encoded)
	sensitive := err != nil || !bytes.Equal(masked, encoded)
	if len(s.sensitive) < maxProbedKeys {
		s.sensitive[key] = sensitive
	}
	return sensitive
}

// value adds findings for value, which starts at start in its line, under key:
// all of it when the key is sensitive, otherwise what the scanner finds in
// "key: value", where the key can select a detector.
func (s *structure) value(found []embargo.Finding, key string, value []byte, start int, sensitive bool) []embargo.Finding {
	if len(value) == 0 {
		return found
	}
	if sensitive || s.keySensitive(key) {
		return append(found, embargo.Finding{Kind: embargo.KindCredential, Start: start, End: start + len(value), Confidence: keyConfidence})
	}
	prefix := len(key) + len(": ")
	text := make([]byte, 0, prefix+len(value))
	text = append(append(append(text, key...), ": "...), value...)
	for _, f := range s.scanner.Scan(text) {
		if f.End > prefix {
			f.Start, f.End = start+max(f.Start-prefix, 0), start+f.End-prefix
			found = append(found, f)
		}
	}
	return found
}

// mergeFindings adds to base the extra findings that no finding of base
// already covers.
func mergeFindings(base, extra []embargo.Finding) []embargo.Finding {
	merged := base
	for _, f := range extra {
		covered := false
		for _, g := range base {
			if g.Start <= f.Start && f.End <= g.End {
				covered = true
				break
			}
		}
		if !covered {
			merged = append(merged, f)
		}
	}
	return merged
}

// jsonFrame is one open object or array. key is the member name an array or
// the next object value belongs to; sensitive marks everything under a
// sensitive key, as MaskJSON masks a whole container.
type jsonFrame struct {
	key       string
	array     bool
	sensitive bool
	// keyLine marks a key read on an earlier line than its value.
	keyLine  bool
	afterKey bool
}

// jsonDocument tracks a JSON document that spans lines. It starts at a line
// that opens an object or array without closing it and stops at its end or
// at the first byte that is not JSON, after which lines are text again.
type jsonDocument struct {
	frames []jsonFrame
}

func (d *jsonDocument) depth() int { return len(d.frames) }

// line reads one line of the document, or starts one, and adds findings for
// values whose key came from an earlier line or that sit in an array or
// object under a sensitive key. A value on its key's line is left to the
// line's own scan, which sees "key": value.
func (d *jsonDocument) line(s *structure, body []byte, found []embargo.Finding) []embargo.Finding {
	if len(d.frames) == 0 && !startsDocument(body) {
		return found
	}
	added := found
	for i := 0; i < len(body); {
		next, ok := d.token(s, body, i, &added)
		if !ok {
			d.frames = nil
			return found
		}
		i = next
	}
	for i := range d.frames {
		if d.frames[i].afterKey {
			d.frames[i].keyLine = true
		}
	}
	return added
}

// startsDocument reports whether body opens an object or array, possibly
// after a key, that it does not close on the same line.
func startsDocument(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && !json.Valid(trimmed)
}

// token reads the token at i and returns the index after it, or false when
// the bytes are not JSON.
func (d *jsonDocument) token(s *structure, body []byte, i int, found *[]embargo.Finding) (int, bool) {
	switch c := body[i]; c {
	case ' ', '\t', '\r':
		return i + 1, true
	case '{', '[':
		d.push(s, c == '[')
		return i + 1, true
	case '}', ']':
		return i + 1, d.pop(c == ']')
	case ',', ':':
		return i + 1, len(d.frames) > 0
	case '"':
		end := stringEnd(body, i)
		if end < 0 || len(d.frames) == 0 {
			return 0, false
		}
		return end, d.scalar(s, body, i, end, true, found)
	default:
		end := i
		for end < len(body) && strings.IndexByte("+-.0123456789eEtruefalsn", body[end]) >= 0 {
			end++
		}
		if end == i || len(d.frames) == 0 || !json.Valid(body[i:end]) {
			return 0, false
		}
		return end, d.scalar(s, body, i, end, false, found)
	}
}

// push opens an object or array, which belongs to the key before it and is
// sensitive under a sensitive key.
func (d *jsonDocument) push(s *structure, array bool) {
	frame := jsonFrame{key: "", array: array, sensitive: false, keyLine: false, afterKey: false}
	if len(d.frames) > 0 {
		parent := &d.frames[len(d.frames)-1]
		frame.sensitive = parent.sensitive || (parent.afterKey || parent.array) && s.keySensitive(parent.key)
		frame.key = parent.key
		parent.afterKey = false
	}
	d.frames = append(d.frames, frame)
}

// pop closes the innermost frame, reporting false when it is not of the kind
// being closed.
func (d *jsonDocument) pop(array bool) bool {
	if len(d.frames) == 0 || d.frames[len(d.frames)-1].array != array {
		return false
	}
	d.frames = d.frames[:len(d.frames)-1]
	return true
}

// scalar handles the string or literal body[start:end]: an object key, or a
// value that gets findings when its key was on an earlier line or it sits
// under a sensitive key or in an array. It returns false for a key that is
// not a JSON string.
func (d *jsonDocument) scalar(s *structure, body []byte, start, end int, quoted bool, found *[]embargo.Finding) bool {
	frame := &d.frames[len(d.frames)-1]
	if !frame.array && !frame.afterKey {
		var key string
		if !quoted || json.Unmarshal(body[start:end], &key) != nil {
			return false
		}
		frame.key, frame.afterKey, frame.keyLine = key, true, false
		return true
	}
	crossLine := frame.array || frame.keyLine
	frame.afterKey, frame.keyLine = false, false
	if !frame.sensitive && !crossLine {
		return true
	}
	value := body[start:end]
	if quoted {
		start, value = start+1, value[1:len(value)-1]
	}
	*found = s.value(*found, frame.key, value, start, frame.sensitive)
	return true
}

// stringEnd returns the index after the closing quote of the string that
// starts at body[i], or -1 when the line ends inside it.
func stringEnd(body []byte, i int) int {
	for j := i + 1; j < len(body); j++ {
		switch body[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return -1
}

// yamlBlock tracks the lines under a sensitive YAML key whose value is a
// block scalar such as | or >-, or is empty and continues on the following
// lines. Every line of a block scalar is masked, and so are "- item" items
// and plain continuation lines; a nested "key: value" line is decided by its
// own key, as a configuration map under session: holds public settings.
type yamlBlock struct {
	indent int
	open   bool
	// literal is set for | and >, whose lines are all text.
	literal bool
}

// line reads one line, adding findings inside an open block, and opens a
// block after a sensitive key with no value on its line.
func (b *yamlBlock) line(s *structure, body []byte, found []embargo.Finding) []embargo.Finding {
	indent := leadingSpaces(body)
	content := bytes.TrimRight(body[indent:], " \t\r")
	if b.open {
		if len(content) == 0 {
			return found
		}
		if indent > b.indent {
			return b.inside(body[:indent+len(content)], indent, found)
		}
		b.open = false
	}
	key, valueStart, ok := yamlKey(content)
	if !ok || !s.keySensitive(key) {
		return found
	}
	value := content[valueStart:]
	if comment := bytes.Index(value, []byte(" #")); comment >= 0 {
		value = bytes.TrimSpace(value[:comment])
	}
	switch {
	case len(value) == 0:
		b.indent, b.open, b.literal = indent, true, false
	case blockIndicator(value):
		b.indent, b.open, b.literal = indent, true, true
	}
	return found
}

// inside adds the finding for one more-indented line of an open block, whose
// content is line[start:], trimmed and not empty.
func (b *yamlBlock) inside(line []byte, start int, found []embargo.Finding) []embargo.Finding {
	end := len(line)
	if !b.literal {
		if bytes.HasPrefix(line[start:], []byte("- ")) {
			start += len("- ")
			start += leadingSpaces(line[start:])
		}
		if _, _, ok := yamlKey(line[start:]); ok || line[start] == '#' {
			// A nested mapping, such as session: with timeout: 30 under it,
			// is decided by its own keys.
			return found
		}
		if comment := bytes.Index(line[start:], []byte(" #")); comment >= 0 {
			end = start + comment
		}
	}
	return append(found, embargo.Finding{Kind: embargo.KindCredential, Start: start, End: end, Confidence: keyConfidence})
}

func leadingSpaces(body []byte) int {
	n := 0
	for n < len(body) && body[n] == ' ' {
		n++
	}
	return n
}

// yamlKey splits "key: value" or "key:", whose key may be quoted, and returns
// where the value starts in content with its trailing comment removed; the
// value is empty when only a comment follows.
func yamlKey(content []byte) (key string, valueStart int, ok bool) {
	colon := bytes.IndexByte(content, ':')
	if colon <= 0 || (colon+1 < len(content) && content[colon+1] != ' ') {
		return "", 0, false
	}
	name := bytes.TrimSpace(content[:colon])
	if len(name) >= 2 && (name[0] == '"' || name[0] == '\'') && name[len(name)-1] == name[0] {
		name = name[1 : len(name)-1]
	}
	if len(name) == 0 || bytes.ContainsAny(name, " \t{}[],") {
		return "", 0, false
	}
	valueStart = colon + 1 + leadingSpaces(content[colon+1:])
	if bytes.HasPrefix(content[valueStart:], []byte("#")) {
		valueStart = len(content)
	}
	return string(name), valueStart, true
}

// blockIndicator reports a block scalar header: | or > with an optional
// chomping indicator and indentation digit in either order.
func blockIndicator(value []byte) bool {
	if len(value) == 0 || (value[0] != '|' && value[0] != '>') || len(value) > 3 {
		return false
	}
	for _, c := range value[1:] {
		if strings.IndexByte("-+123456789", c) < 0 {
			return false
		}
	}
	return true
}

// cefHeaderFields is the number of "|" before a CEF extension.
const cefHeaderFields = 7

// cefFindings adds findings for the custom fields of a CEF event, such as
// cs1Label=password cs1=value, whose label is the key that decides them.
func cefFindings(s *structure, body []byte, found []embargo.Finding) []embargo.Finding {
	header := bytes.Index(body, []byte("CEF:"))
	if header < 0 {
		return found
	}
	extension := header
	for range cefHeaderFields {
		next := unescapedPipe(body, extension)
		if next < 0 {
			return found
		}
		extension = next + 1
	}
	pairs := cefPairs(body, extension)
	labels := make(map[string]string)
	for _, pair := range pairs {
		if name, ok := bytes.CutSuffix(pair.key, []byte("Label")); ok && len(name) > 0 {
			labels[string(name)] = string(body[pair.start:pair.end])
		}
	}
	for _, pair := range pairs {
		if label, ok := labels[string(pair.key)]; ok && label != "" {
			found = s.value(found, label, body[pair.start:pair.end], pair.start, false)
		}
	}
	return found
}

// unescapedPipe returns the index of the next "|" at or after i that no
// backslash escapes, or -1.
func unescapedPipe(body []byte, i int) int {
	for ; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case '|':
			return i
		}
	}
	return -1
}

// cefPair is one key=value of a CEF extension; the value is body[start:end].
type cefPair struct {
	key        []byte
	start, end int
}

// cefPairs splits a CEF extension into its pairs. A value runs to the space
// before the next key=, as an unescaped = only starts a key.
func cefPairs(body []byte, i int) []cefPair {
	var pairs []cefPair
	for i < len(body) {
		for i < len(body) && body[i] == ' ' {
			i++
		}
		equals := i
		for equals < len(body) && cefKeyByte(body[equals]) {
			equals++
		}
		if equals == i || equals >= len(body) || body[equals] != '=' {
			return pairs
		}
		start, end := equals+1, cefValueEnd(body, equals+1)
		pairs = append(pairs, cefPair{key: body[i:equals], start: start, end: end})
		i = end
	}
	return pairs
}

// cefValueEnd returns where the value that starts at i ends: at the space
// before the next key=, or at the end of the line.
func cefValueEnd(body []byte, i int) int {
	for i < len(body) && (body[i] != ' ' || !nextCEFKey(body, i+1)) {
		if body[i] == '\\' {
			i++
		}
		i++
	}
	return min(i, len(body))
}

// cefKeyAlphabet holds the bytes of a CEF extension key.
const cefKeyAlphabet = "_.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func cefKeyByte(c byte) bool {
	return strings.IndexByte(cefKeyAlphabet, c) >= 0
}

// nextCEFKey reports whether a key followed by = starts at i.
func nextCEFKey(body []byte, i int) bool {
	j := i
	for j < len(body) && cefKeyByte(body[j]) {
		j++
	}
	return j > i && j < len(body) && body[j] == '='
}
