package embargo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"unicode/utf8"

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
func (s *Scanner) maskJSON(ctx context.Context, data []byte, key string, encoded bool) ([]byte, error) {
	if s == nil {
		return nil, jsonFailure()
	}
	policy := newFieldPolicy(s, "")
	defer policy.release()
	return policy.maskJSON(ctx, data, key, encoded)
}

// maskJSON masks one document whose root value is the member value of key
// under the policy's current path, so a document inside another tree, such
// as a slog value, continues that tree's key path.
func (p *fieldPolicy) maskJSON(ctx context.Context, data []byte, key string, encoded bool) (masked []byte, err error) {
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
	if len(data) == 0 || (!encoded && !json.Valid(data)) {
		return nil, jsonFailure()
	}

	data = bytes.TrimSpace(data)
	// The walker works on a copy of the policy, which is written back, so
	// the policy itself can stay on its owner's stack.
	walker := jsonWalker{data: data, result: make([]byte, 0, len(data)), policy: *p}
	walkErr := walker.value(ctx, 0, key, false)
	*p = walker.policy
	if walkErr != nil {
		return nil, walkErr
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
// Unlike a map tree, the walk retains every duplicate key and its value. The
// walker owns the JSON syntax and output; fieldPolicy decides what is masked.
type jsonWalker struct {
	err       error
	pathMasks map[int]Finding
	policy    fieldPolicy
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
	if !hidden && w.policy.sensitive(key) {
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
	masked, hidden, err := w.policy.scan.maskBytes(ctx, raw, key)
	if err != nil {
		return err
	}
	if hidden {
		w.appendString(masked)
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
	var pair namedPair[Finding]
	for w.data[w.pos] != closeByte {
		if err := w.element(ctx, depth, key, open == '{', hidden, &pair); err != nil {
			return err
		}
	}
	w.pos++
	if !hidden {
		pair.hidden(w.maskSpan)
		w.appendResult([]byte{closeByte})
	}
	return nil
}

// element walks one array element or object member and the separator after it.
func (w *jsonWalker) element(ctx context.Context, depth int, key string, member, hidden bool, pair *namedPair[Finding]) error {
	fieldContext := key
	entered := member && !hidden
	var keySpan Finding
	if member {
		var err error
		if fieldContext, keySpan, err = w.memberKey(ctx, key, hidden); err != nil {
			return err
		}
	}
	w.space()
	valueStart, resultStart := w.pos, len(w.result)
	if err := w.value(ctx, depth+1, fieldContext, hidden); err != nil {
		return err
	}
	if entered {
		if w.policy.leave() {
			w.maskSpan(keySpan)
		}
		raw := w.data[valueStart:w.pos]
		switch namedValueField(fieldContext) {
		case pairName:
			if name, ok := jsonName(raw); ok {
				pair.name(&w.policy, name)
			}
		case pairValue:
			pair.value(jsonValueShape(raw), Finding{Start: resultStart, End: len(w.result)})
		case pairNone:
		}
	}
	w.space()
	w.elementSeparator(hidden)
	return nil
}

// maskSpan writes the marker over an output span when the walk completes; a
// failed walk returns no output, so its spans are never applied.
func (w *jsonWalker) maskSpan(span Finding) {
	if w.pathMasks == nil {
		w.pathMasks = make(map[int]Finding)
	}
	w.pathMasks[span.Start] = span
}

// memberKey consumes an object key and its colon. A visible key is masked,
// entered into the policy path and becomes the field context, and keySpan is
// its output span; under a hidden parent the enclosing key stays.
func (w *jsonWalker) memberKey(ctx context.Context, key string, hidden bool) (fieldContext string, keySpan Finding, err error) {
	raw := w.stringToken()
	fieldContext = key
	if !hidden {
		start := len(w.result)
		fieldContext, err = w.objectKey(ctx, raw)
		if err != nil {
			return "", Finding{}, err
		}
		keySpan = Finding{Start: start, End: len(w.result)}
		w.appendResult([]byte{':'})
	}
	w.space()
	w.pos++ // Colon, already checked by json.Valid.
	return fieldContext, keySpan, nil
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
		return w.stringValue(ctx, raw, key)
	}
	masked, changed, err := w.policy.scan.maskBytes(ctx, content, key)
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
func (w *jsonWalker) stringValue(ctx context.Context, raw []byte, key string) error {
	text, err := decodeJSONString(raw)
	if err != nil {
		return err
	}
	masked, err := w.policy.scan.maskScalar(ctx, text, key)
	if err != nil {
		return err
	}
	w.appendText(raw, text, masked)
	return w.err
}

func decodeJSONString(raw []byte) (string, error) {
	text := string(raw[1 : len(raw)-1])
	if bytes.IndexByte(raw, '\\') >= 0 || !utf8.ValidString(text) {
		if err := json.Unmarshal(raw, &text); err != nil {
			return "", saferecord.ErrMasking
		}
	}
	return text, nil
}

// appendText reuses an unchanged JSON lexeme and escapes a changed string with
// encoding/json; invalid UTF-8 is normalized by the decoder before it reaches
// the output.
func (w *jsonWalker) appendText(raw []byte, text, masked string) {
	if masked == text && utf8.Valid(raw) {
		w.appendResult(raw)
	} else {
		w.appendString(masked)
	}
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

// objectKey writes a masked object key and enters it into the policy path.
func (w *jsonWalker) objectKey(ctx context.Context, raw []byte) (string, error) {
	if content := raw[1 : len(raw)-1]; bytes.IndexByte(content, '\\') < 0 && utf8.Valid(content) {
		// A cached key had no findings, so its lexeme is copied unchanged.
		decision, ok, err := w.policy.cachedMember(ctx, content)
		if err != nil {
			return "", err
		}
		if ok {
			w.appendResult(raw)
			return decision.key, w.err
		}
	}
	text, err := decodeJSONString(raw)
	if err != nil {
		return "", err
	}
	decision, err := w.policy.member(ctx, text)
	if err != nil {
		return "", err
	}
	w.appendText(raw, text, decision.masked)
	return text, w.err
}
