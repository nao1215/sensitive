package embargo

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
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

func jsonFailure() error { return errors.New("embargo: invalid or unmaskable JSON log event") }

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
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
		if !complete {
			masked = nil
			err = jsonFailure()
		}
	}()
	if len(data) > maxEventBytes {
		return nil, jsonFailure()
	}
	data = bytes.TrimSpace(data)
	if scanner == nil || len(data) == 0 || !json.Valid(data) {
		return nil, jsonFailure()
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	masked, err = readValue(decoder, &eventScanner{scanner: scanner, remaining: maxScanBytes}, 0, "")
	if err != nil || len(masked) > maxEventBytes {
		return nil, jsonFailure()
	}
	complete = true
	return masked, nil
}

func readValue(decoder *json.Decoder, scanner *eventScanner, depth int, context string) ([]byte, error) {
	if depth > maxDepth {
		return nil, jsonFailure()
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, jsonFailure()
	}
	if context != "" && scanner.scanner.sensitiveKey(context) {
		if delimiter, ok := token.(json.Delim); ok {
			if err := skipJSONContainer(decoder, depth, delimiter); err != nil {
				return nil, err
			}
		}
		return []byte(`"` + redactionMarker + `"`), nil
	}
	switch value := token.(type) {
	case json.Delim:
		return readContainer(decoder, scanner, depth, value, context)
	case string:
		masked, err := scanner.maskScalar(value, context)
		if err != nil {
			return nil, err
		}
		return json.Marshal(masked)
	case json.Number:
		text := value.String()
		masked, err := scanner.maskScalar(text, context)
		if err != nil {
			return nil, err
		}
		if masked != text {
			return json.Marshal(masked)
		}
		return []byte(text), nil
	case bool:
		return []byte(strconv.FormatBool(value)), nil
	case nil:
		return []byte("null"), nil
	default:
		return nil, jsonFailure()
	}
}

func readContainer(decoder *json.Decoder, scanner *eventScanner, depth int, open json.Delim, context string) ([]byte, error) {
	result := []byte(open.String())
	first := true
	for decoder.More() {
		if !first {
			result = append(result, ',')
		}
		first = false
		fieldContext := context
		if open == '{' {
			token, err := decoder.Token()
			if err != nil {
				return nil, jsonFailure()
			}
			key, ok := token.(string)
			if !ok {
				return nil, jsonFailure()
			}
			fieldContext = key
			masked, err := scanner.maskScalar(key, "")
			if err != nil {
				return nil, err
			}
			//nolint:errchkjson // Keep the explicit error check required by strict errcheck.
			maskedKey, err := json.Marshal(masked)
			if err != nil {
				return nil, jsonFailure()
			}
			result = append(result, maskedKey...)
			result = append(result, ':')
		}
		value, err := readValue(decoder, scanner, depth+1, fieldContext)
		if err != nil {
			return nil, err
		}
		result = append(result, value...)
		if len(result) > maxEventBytes {
			return nil, jsonFailure()
		}
	}
	closeToken, err := decoder.Token()
	if err != nil {
		return nil, jsonFailure()
	}
	closeDelimiter, ok := closeToken.(json.Delim)
	if !ok {
		return nil, jsonFailure()
	}
	return append(result, closeDelimiter.String()...), nil
}

// Include the field name so context-based detectors can recognize, for example,
// {"cvv":123}. Translate findings back to value bytes before replacing them.
func (s *eventScanner) maskScalar(value, context string) (string, error) {
	// Charge before allocating the prefix or invoking any detector.
	prefixBytes := 0
	if context != "" {
		prefixBytes = len(context) + len(": ")
	}
	if prefixBytes > s.remaining || len(value) > s.remaining-prefixBytes {
		return "", jsonFailure()
	}
	s.remaining -= prefixBytes + len(value)
	if prefixBytes == 0 {
		return Mask(value, s.scanner.ScanString(value)), nil
	}
	prefix := context + ": "
	findings := s.scanner.ScanString(prefix + value)
	spans := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.End <= len(prefix) {
			continue
		}
		finding.Start = max(0, finding.Start-len(prefix))
		finding.End -= len(prefix)
		spans = append(spans, finding)
	}
	return Mask(value, spans), nil
}

// Hidden containers still obey the nesting bound, but do not invoke detectors.
func skipJSONContainer(decoder *json.Decoder, depth int, open json.Delim) error {
	if depth > maxDepth {
		return jsonFailure()
	}
	for decoder.More() {
		if open == '{' {
			if _, err := decoder.Token(); err != nil {
				return jsonFailure()
			}
		}
		if depth == maxDepth {
			return jsonFailure()
		}
		token, err := decoder.Token()
		if err != nil {
			return jsonFailure()
		}
		if delimiter, ok := token.(json.Delim); ok {
			if err := skipJSONContainer(decoder, depth+1, delimiter); err != nil {
				return err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return jsonFailure()
	}
	return nil
}
