package embargo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

const (
	maxEventBytes = 1 << 20
	maxDepth      = 64
	maxScanBytes  = 4 * maxEventBytes
)

type eventScanner struct {
	scanner   *Scanner
	remaining int
}

func jsonFailure() error { return errors.New("embargo: invalid or unmaskable JSON") }

// MaskJSON masks one JSON document using this scanner's detectors and sensitive
// key policy. It preserves object order, duplicate keys, arrays, nulls, booleans
// and clean numbers without rounding. Sensitive numbers become marker strings;
// a sensitive key replaces its entire value, including containers, with a marker.
// The returned compact JSON owns its bytes and has no trailing newline.
// Input and output are limited to 1 MiB, nesting to 64, and cumulative detector
// input to 4 MiB. Invalid input, exceeded limits and panics return no bytes and a
// fixed error without input data. It does not modify the source document.
// Use it before sending JSON API responses, exports or audit records.
func (scanner *Scanner) MaskJSON(data []byte) (masked []byte, err error) {
	return scanner.MaskJSONContext(context.Background(), data)
}

// MaskJSONContext applies MaskJSON's policy while checking ctx before and between
// scalar scans. A canceled or nil context returns no bytes and a fixed error.
// An already running detector cannot be interrupted.
// Use it for request-scoped or telemetry work that should stop after cancellation.
func (scanner *Scanner) MaskJSONContext(ctx context.Context, data []byte) ([]byte, error) {
	return scanner.maskJSON(ctx, data, "")
}

func (scanner *Scanner) maskJSON(ctx context.Context, data []byte, key string) (masked []byte, err error) {
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
		if !complete {
			masked = nil
			err = jsonFailure()
		}
	}()
	if ctx == nil || ctx.Err() != nil || len(data) > maxEventBytes {
		return nil, jsonFailure()
	}
	if scanner == nil || len(data) == 0 || !json.Valid(data) {
		return nil, jsonFailure()
	}

	data = bytes.TrimSpace(data)
	walker := jsonWalker{data: data, result: make([]byte, 0, len(data)), scanner: eventScanner{scanner: scanner, remaining: maxScanBytes}}
	if err := walker.value(ctx, 0, key, false); err != nil {
		return nil, jsonFailure()
	}
	complete = true
	return walker.result, nil
}

// json.Valid establishes grammar and bounds before this allocation-light walk.
// Original numeric lexemes are retained, equivalent to decoding with UseNumber.
// Unlike a map tree, the walk retains every duplicate key and its value.
type jsonWalker struct {
	scanner eventScanner
	data    []byte
	result  []byte
	pos     int
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
	if ctx.Err() != nil || depth > maxDepth {
		return jsonFailure()
	}
	w.space()
	if !hidden && key != "" && w.scanner.scanner.sensitiveKey(key) {
		w.result = append(w.result, `"`+redactionMarker+`"`...)
		hidden = true
	}
	switch w.data[w.pos] {
	case '{', '[':
		if err := w.container(ctx, depth, key, hidden); err != nil {
			return err
		}
	case '"':
		raw := w.stringToken()
		if !hidden {
			if _, err := w.stringValue(ctx, raw, key); err != nil {
				return err
			}
		}
	default:
		start := w.pos
		for w.pos < len(w.data) {
			c := w.data[w.pos]
			if c == ',' || c == ']' || c == '}' || c == ' ' || c == '\n' || c == '\r' || c == '\t' {
				break
			}
			w.pos++
		}
		if !hidden {
			if err := w.scalar(ctx, w.data[start:w.pos], key); err != nil {
				return err
			}
		}
	}
	if len(w.result) > maxEventBytes {
		return jsonFailure()
	}
	return nil
}

func (w *jsonWalker) scalar(ctx context.Context, raw []byte, key string) error {
	masked, err := w.scanner.maskScalar(ctx, string(raw), key)
	if err != nil {
		return err
	}
	if masked == string(raw) {
		w.result = append(w.result, raw...)
	} else {
		w.appendString(masked)
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
		w.result = append(w.result, open)
	}
	w.space()
	for w.data[w.pos] != closeByte {
		fieldContext := key
		if open == '{' {
			raw := w.stringToken()
			if !hidden {
				var err error
				fieldContext, err = w.stringValue(ctx, raw, "")
				if err != nil {
					return err
				}
				w.result = append(w.result, ':')
			}
			w.space()
			w.pos++ // Colon, already checked by json.Valid.
		}
		if err := w.value(ctx, depth+1, fieldContext, hidden); err != nil {
			return err
		}
		w.space()
		if w.data[w.pos] == ',' {
			w.pos++
			if !hidden {
				w.result = append(w.result, ',')
			}
			w.space()
		}
	}
	w.pos++
	if !hidden {
		w.result = append(w.result, closeByte)
	}
	return nil
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

// Decode escaped strings using encoding/json; plain UTF-8 needs no decoder.
func (w *jsonWalker) stringValue(ctx context.Context, raw []byte, key string) (string, error) {
	text := string(raw[1 : len(raw)-1])
	if bytes.IndexByte(raw, '\\') >= 0 || !utf8.ValidString(text) {
		if err := json.Unmarshal(raw, &text); err != nil {
			return "", jsonFailure()
		}
	}
	masked, err := w.scanner.maskScalar(ctx, text, key)
	if err != nil {
		return "", err
	}
	// Reuse unchanged JSON lexemes. Escape changed strings with encoding/json;
	// invalid UTF-8 is normalized by the decoder before it reaches the output.
	if masked == text && utf8.Valid(raw) {
		w.result = append(w.result, raw...)
	} else {
		w.appendString(masked)
	}
	return text, nil
}

func (w *jsonWalker) appendString(text string) {
	// Marshaling a string cannot fail. Keep the explicit boundary for panics.
	//nolint:errchkjson // Keep the explicit error check required by strict errcheck.
	encoded, err := json.Marshal(text)
	if err != nil {
		panic("embargo: JSON string encoding failed")
	}
	w.result = append(w.result, encoded...)
}

// Include the field name so context-based detectors can recognize, for example,
// {"cvv":123}. Translate findings back to value bytes before replacing them.
func (s *eventScanner) maskScalar(ctx context.Context, value, key string) (string, error) {
	if ctx.Err() != nil {
		return "", jsonFailure()
	}
	// Charge before allocating the prefix or invoking any detector.
	prefixBytes := 0
	if key != "" {
		prefixBytes = len(key) + len(": ")
	}
	if prefixBytes > s.remaining || len(value) > s.remaining-prefixBytes {
		return "", jsonFailure()
	}
	s.remaining -= prefixBytes + len(value)
	if prefixBytes == 0 {
		findings := s.scanner.scan([]byte(value), ctx.Err)
		if ctx.Err() != nil {
			return "", jsonFailure()
		}
		return Mask(value, findings), nil
	}
	findings := s.scanner.scan([]byte(key+": "+value), ctx.Err)
	if ctx.Err() != nil {
		return "", jsonFailure()
	}
	spans := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.End <= prefixBytes {
			continue
		}
		finding.Start = max(0, finding.Start-prefixBytes)
		finding.End -= prefixBytes
		spans = append(spans, finding)
	}
	return Mask(value, spans), nil
}
