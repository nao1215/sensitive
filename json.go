package embargo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/nao1215/embargo/internal/ascii"
	"github.com/nao1215/embargo/internal/saferecord"
)

func jsonFailure() error { return saferecord.ErrMasking }

// MaskJSON returns a compact copy of one JSON document with sensitive values masked,
// keeping object order, duplicate keys, types and clean numbers exactly; a value under
// a sensitive key becomes a marker, and a sensitive number becomes a marker string.
// Input and output are limited to 1 MiB and nesting to 64. Invalid input or an
// exceeded limit returns no bytes and a fixed error that contains no input data.
// Use it before sending JSON API responses, exports or audit records; the
// [logging guide] describes the remaining bounds.
//
// [logging guide]: https://github.com/nao1215/embargo/blob/main/doc/logging.md#bounds-and-failures
func (s *Scanner) MaskJSON(data []byte) ([]byte, error) {
	return s.MaskJSONContext(context.Background(), data)
}

// MaskJSONContext applies MaskJSON's policy while checking ctx before and between
// scalar scans. A canceled or nil context returns no bytes and a fixed error,
// which errors.Is matches with the context's error, such as context.Canceled.
// An already running detector cannot be interrupted.
// Use it for request-scoped or telemetry work that should stop after cancellation.
func (s *Scanner) MaskJSONContext(ctx context.Context, data []byte) ([]byte, error) {
	masked, err := s.maskJSON(ctx, data, "", false)
	if errors.Is(err, saferecord.ErrCanceled) {
		err = saferecord.Canceled(ctx)
	}
	return masked, err
}

// maskJSON masks one document. encoded is true only for encoding/json output,
// which that package has already validated and compacted, so json.Valid would
// repeat its work.
func (s *Scanner) maskJSON(ctx context.Context, data []byte, key string, encoded bool) (masked []byte, err error) {
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
		if !complete {
			masked = nil
			if err == nil {
				err = jsonFailure()
			}
		}
	}()
	if ctx == nil || ctx.Err() != nil {
		return nil, saferecord.ErrCanceled
	}
	if len(data) > maxEventBytes {
		return nil, saferecord.ErrSizeLimit
	}
	if s == nil || len(data) == 0 || (!encoded && !json.Valid(data)) {
		return nil, jsonFailure()
	}

	data = bytes.TrimSpace(data)
	walker := jsonWalker{data: data, result: make([]byte, 0, len(data)), scanner: eventScanner{scanner: s, remaining: maxScanBytes}}
	if err := walker.value(ctx, 0, key, false); err != nil {
		return nil, err
	}
	complete = true
	if len(walker.pathMasks) == 0 {
		return walker.result, nil
	}
	spans := make([]Finding, 0, len(walker.pathMasks))
	for _, span := range walker.pathMasks {
		spans = append(spans, span)
	}
	masked = []byte(MaskFunc(string(walker.result), spans, func(Kind, string) string { return `"` + redactionMarker + `"` }))
	if len(masked) > maxEventBytes {
		return nil, saferecord.ErrSizeLimit
	}
	return masked, nil
}

// json.Valid establishes grammar and bounds before this allocation-light walk.
// Original numeric lexemes are retained, equivalent to decoding with UseNumber.
// Unlike a map tree, the walk retains every duplicate key and its value.
type jsonKeyPosition struct {
	path       string
	start, end int
}

type jsonWalker struct {
	path      []jsonKeyPosition
	pathMasks map[int]Finding
	err       error
	scanner   eventScanner
	data      []byte
	result    []byte
	pos       int
}

func (w *jsonWalker) space() {
	for w.pos < len(w.data) {
		switch w.data[w.pos] {
		case ' ', '\t', '\r', '\n':
			w.pos++
		default:
			return
		}
	}
}

func (w *jsonWalker) value(ctx context.Context, depth int, key string, hidden bool) error {
	if w.err != nil {
		return w.err
	}
	if ctx.Err() != nil {
		return saferecord.ErrCanceled
	}
	if depth > maxDepth {
		return saferecord.ErrSizeLimit
	}
	w.space()
	if !hidden && key != "" && w.scanner.scanner.cachedSensitiveKey(key) {
		w.appendResult([]byte(`"` + redactionMarker + `"`))
		hidden = true
	}
	switch w.data[w.pos] {
	case '{', '[':
		if err := w.container(ctx, depth, key, hidden); err != nil {
			return err
		}
	case '"':
		if err := w.stringField(ctx, key, hidden); err != nil {
			return err
		}
	default:
		if err := w.literal(ctx, key, hidden); err != nil {
			return err
		}
	}
	return w.err
}

// stringField consumes a string value and masks it unless a sensitive key
// above it already replaced the whole value.
func (w *jsonWalker) stringField(ctx context.Context, key string, hidden bool) error {
	raw := w.stringToken()
	if hidden {
		return nil
	}
	return w.stringElement(ctx, raw, key)
}

// literal consumes a number, boolean or null lexeme, which ends at the first
// structural delimiter or whitespace byte, and masks it unless hidden;
// json.Valid owns its grammar.
func (w *jsonWalker) literal(ctx context.Context, key string, hidden bool) error {
	start := w.pos
	for w.pos < len(w.data) {
		c := w.data[w.pos]
		if c == ',' || c == ']' || c == '}' || c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			break
		}
		w.pos++
	}
	if hidden {
		return nil
	}
	return w.scalar(ctx, w.data[start:w.pos], key)
}

func (w *jsonWalker) scalar(ctx context.Context, raw []byte, key string) error {
	_, hidden, err := w.scanner.maskBytes(ctx, raw, key)
	if err != nil {
		return err
	}
	if hidden {
		w.appendString(redactionMarker)
	} else {
		w.appendResult(raw)
	}
	return nil
}

func (w *jsonWalker) container(ctx context.Context, depth int, key string, hidden bool) error {
	open := w.data[w.pos]
	w.pos++
	closeByte := byte(']')
	if open == '{' {
		closeByte = '}'
	}
	if !hidden {
		w.appendResult([]byte{open})
		if w.err != nil {
			return w.err
		}
	}
	w.space()
	pair := namedValue{active: open == '{' && !hidden, sensitive: false, valueStart: 0, valueEnd: 0}
	for w.data[w.pos] != closeByte {
		if err := w.element(ctx, depth, key, open == '{', hidden, &pair); err != nil {
			return err
		}
	}
	w.pos++
	if !hidden {
		pair.mask(w)
		w.appendResult([]byte{closeByte})
	}
	return nil
}

// element walks one array element or object member and the separator after it.
func (w *jsonWalker) element(ctx context.Context, depth int, key string, member, hidden bool, pair *namedValue) error {
	fieldContext := key
	pathDepth := len(w.path)
	if member {
		var err error
		if fieldContext, err = w.memberKey(ctx, key, hidden); err != nil {
			return err
		}
	}
	w.space()
	valueStart, resultStart := w.pos, len(w.result)
	if err := w.value(ctx, depth+1, fieldContext, hidden); err != nil {
		return err
	}
	pair.member(w, fieldContext, w.data[valueStart:w.pos], resultStart)
	w.path = w.path[:pathDepth]
	w.space()
	w.elementSeparator(hidden)
	return nil
}

// namedValue tracks one object that stores a setting as separate name and
// value members, as Kubernetes env, ECS task definitions, SSM parameters and
// CloudFormation parameters do: {"name":"DB_PASSWORD","value":"hunter2"}.
// The value is masked when the name is a sensitive key, in either member
// order: a string, or a whole object or array as under a sensitive key.
// Numeric values, as in metric samples, stay visible.
type namedValue struct {
	active     bool
	sensitive  bool
	valueStart int
	valueEnd   int
}

// member records a name member whose string is a sensitive key and the
// output span of a value member that is a non-empty string or a container.
func (p *namedValue) member(w *jsonWalker, key string, raw []byte, resultStart int) {
	if !p.active {
		return
	}
	switch namedValueField(key) {
	case pairName:
		var name string
		if json.Unmarshal(raw, &name) == nil && w.scanner.scanner.cachedSensitiveKey(settingName(name)) {
			p.sensitive = true
		}
	case pairValue:
		// raw is a whole JSON value, so it is never empty.
		if raw[0] == '{' || raw[0] == '[' || (raw[0] == '"' && len(raw) > len(`""`)) {
			p.valueStart, p.valueEnd = resultStart, len(w.result)
		}
	case pairNone:
	}
}

// pairField classifies a member of a name and value pair.
type pairField uint8

const (
	pairNone pairField = iota
	pairName
	pairValue
)

// namedValueField lowers a short member key and drops separators, as
// normalizeKey does, without allocating; longer keys are never pair members.
func namedValueField(key string) pairField {
	var folded [len("parametervalue")]byte
	n := 0
	for i := range len(key) {
		c := key[i]
		if c == '_' || c == '-' || c == '.' || c == ' ' {
			continue
		}
		if n == len(folded) {
			return pairNone
		}
		folded[n] = ascii.ToLower(c)
		n++
	}
	switch string(folded[:n]) {
	case "name", "key", "parameterkey", "parametername", "optionname", "variable":
		return pairName
	case "value", "parametervalue":
		return pairValue
	}
	return pairNone
}

// mask hides the recorded value span once both members were seen.
func (p *namedValue) mask(w *jsonWalker) {
	if !p.sensitive || p.valueEnd == 0 || w.err != nil {
		return
	}
	if w.pathMasks == nil {
		w.pathMasks = make(map[int]Finding)
	}
	w.pathMasks[p.valueStart] = Finding{Start: p.valueStart, End: p.valueEnd}
}

// settingName keeps the last segment of a parameter path such as
// /prod/db/password, so the key rule sees the setting rather than the path.
func settingName(name string) string {
	return name[strings.LastIndexByte(name, '/')+1:]
}

// memberKey consumes an object key and its colon. A visible key is masked and
// becomes the field context; under a hidden parent the enclosing key stays.
func (w *jsonWalker) memberKey(ctx context.Context, key string, hidden bool) (string, error) {
	raw := w.stringToken()
	fieldContext := key
	if !hidden {
		var err error
		fieldContext, err = w.objectKey(ctx, raw)
		if err != nil {
			return "", err
		}
		w.appendResult([]byte{':'})
	}
	w.space()
	w.pos++ // Colon, already checked by json.Valid.
	return fieldContext, nil
}

// elementSeparator consumes a comma between container elements, copying it
// only when the container is visible.
func (w *jsonWalker) elementSeparator(hidden bool) {
	if w.data[w.pos] == ',' {
		w.pos++
		if !hidden {
			w.appendResult([]byte{','})
		}
		w.space()
	}
}

func (w *jsonWalker) stringToken() []byte {
	start := w.pos
	w.pos++
	for w.data[w.pos] != '"' {
		if w.data[w.pos] == '\\' {
			w.pos++
		}
		w.pos++
	}
	w.pos++
	return w.data[start:w.pos]
}

// stringElement masks a string value. A plain UTF-8 lexeme is scanned in place
// and copied unchanged when clean; others take stringValue's decoding path.
func (w *jsonWalker) stringElement(ctx context.Context, raw []byte, key string) error {
	content := raw[1 : len(raw)-1]
	if bytes.IndexByte(content, '\\') >= 0 || !utf8.Valid(content) {
		_, err := w.stringValue(ctx, raw, key, false)
		return err
	}
	masked, changed, err := w.scanner.maskBytes(ctx, content, key)
	if err != nil {
		return err
	}
	if changed {
		w.appendString(masked)
	} else {
		w.appendResult(raw)
	}
	return w.err
}

// Decode escaped strings using encoding/json; plain UTF-8 needs no decoder.
func (w *jsonWalker) stringValue(ctx context.Context, raw []byte, key string, objectKey bool) (string, error) {
	text := string(raw[1 : len(raw)-1])
	if bytes.IndexByte(raw, '\\') >= 0 || !utf8.ValidString(text) {
		if err := json.Unmarshal(raw, &text); err != nil {
			return "", saferecord.ErrMasking
		}
	}
	masked, err := w.maskText(ctx, text, key, objectKey)
	if err != nil {
		return "", err
	}
	// Reuse unchanged JSON lexemes. Escape changed strings with encoding/json;
	// invalid UTF-8 is normalized by the decoder before it reaches the output.
	if masked == text && utf8.Valid(raw) {
		w.appendResult(raw)
	} else {
		w.appendString(masked)
	}
	return text, w.err
}

// maskText masks a decoded string; object keys, scanned without a field
// context, use the scanner's key cache.
func (w *jsonWalker) maskText(ctx context.Context, text, key string, objectKey bool) (string, error) {
	if !objectKey {
		return w.scanner.maskScalar(ctx, text, key)
	}
	result, err := w.scanner.maskCached(ctx, text)
	return result.masked, err
}

func (w *jsonWalker) appendString(text string) {
	if plainJSONText(text) {
		// Same bytes and limit as appendResult(json.Marshal(text)), without the copy.
		if w.err == nil && len(text)+len(`""`) > maxEventBytes-len(w.result) {
			w.err = saferecord.ErrSizeLimit
		}
		if w.err == nil {
			w.result = append(append(append(w.result, '"'), text...), '"')
		}
		return
	}
	// Marshaling a string cannot fail. Keep the explicit boundary for panics.
	//nolint:errchkjson // Keep the explicit error check required by strict errcheck.
	encoded, err := json.Marshal(text)
	if err != nil {
		panic("embargo: JSON string encoding failed")
	}
	w.appendResult(encoded)
}

// plainJSONText reports whether encoding/json writes text unchanged between
// quotes: printable ASCII without quote, backslash or the HTML-escaped <, > and &.
func plainJSONText(text string) bool {
	for i := range len(text) {
		if c := text[i]; c < ' ' || c >= utf8.RuneSelf || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			return false
		}
	}
	return true
}

// Stop before retaining bytes beyond the output limit, including a token that
// expands during masking. Callers check the failure before scanning another value.
func (w *jsonWalker) appendResult(data []byte) {
	if w.err != nil {
		return
	}
	if len(data) > maxEventBytes-len(w.result) {
		w.err = saferecord.ErrSizeLimit
		return
	}
	w.result = append(w.result, data...)
}

// Keep original keys for path detection and output ranges for replacing every segment.
func (w *jsonWalker) keyPath(ctx context.Context, key string, start, end int) error {
	path := key
	if len(w.path) > 0 {
		path = joinedKey(w.path[len(w.path)-1].path, key)
	}
	w.path = append(w.path, jsonKeyPosition{path: path, start: start, end: end})
	if len(w.path) == 1 {
		return nil
	} // Single keys were already scanned by stringValue.
	crossed, err := w.scanner.joinedKeySensitive(ctx, path, len(w.path[len(w.path)-2].path))
	if err != nil {
		return err
	}
	if !crossed {
		return nil
	}
	if w.pathMasks == nil {
		w.pathMasks = make(map[int]Finding)
	}
	for _, segment := range w.path {
		w.pathMasks[segment.start] = Finding{Start: segment.start, End: segment.end}
	}
	return nil
}

func (w *jsonWalker) objectKey(ctx context.Context, raw []byte) (string, error) {
	start := len(w.result)
	if content := raw[1 : len(raw)-1]; bytes.IndexByte(content, '\\') < 0 && utf8.Valid(content) {
		// A cached key had no findings, so its lexeme is copied unchanged.
		result, ok, err := cachedKey(ctx, &w.scanner, content)
		if err != nil {
			return "", err
		}
		if ok {
			w.appendResult(raw)
			if w.err != nil {
				return "", w.err
			}
			return result.key, w.keyPath(ctx, result.key, start, len(w.result))
		}
	}
	original, err := w.stringValue(ctx, raw, "", true)
	if err != nil {
		return "", err
	}
	pathKey := original
	if !bytes.Equal(w.result[start:], raw) {
		pathKey = redactionMarker
	}
	return original, w.keyPath(ctx, pathKey, start, len(w.result))
}
