package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/nao1215/embargo"
)

const (
	maxEventBytes = 1 << 20
	maxDepth      = 64
)

func failure() error { return errors.New("embargo: invalid or unmaskable JSON log event") }

// JSON masks decoded strings (including keys) and numeric representations in one
// JSON object, returning a newline-terminated object. Duplicate keys and clean
// scalar types are preserved. Malformed, oversized, deeply nested or panicking
// input returns a fixed error and no output; panic values are never formatted.
func JSON(data []byte, scanner *embargo.Scanner) (masked []byte, err error) {
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
		if !complete {
			masked = nil
			err = failure()
		}
	}()
	if len(data) > maxEventBytes {
		return nil, failure()
	}
	data = bytes.TrimSpace(data)
	if scanner == nil || len(data) == 0 || data[0] != '{' || !json.Valid(data) {
		return nil, failure()
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	masked, err = readValue(decoder, scanner, 0, "")
	if err != nil || len(masked) >= maxEventBytes {
		return nil, failure()
	}
	masked = append(masked, '\n')
	complete = true
	return masked, nil
}

func readValue(decoder *json.Decoder, scanner *embargo.Scanner, depth int, context string) ([]byte, error) {
	if depth > maxDepth {
		return nil, failure()
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, failure()
	}
	switch value := token.(type) {
	case json.Delim:
		return readContainer(decoder, scanner, depth, value, context)
	case string:
		return json.Marshal(maskScalar(scanner, value, context))
	case json.Number:
		text := value.String()
		masked := maskScalar(scanner, text, context)
		if masked != text {
			return json.Marshal(masked)
		}
		return []byte(text), nil
	case bool:
		return []byte(strconv.FormatBool(value)), nil
	case nil:
		return []byte("null"), nil
	default:
		return nil, failure()
	}
}

func readContainer(decoder *json.Decoder, scanner *embargo.Scanner, depth int, open json.Delim, context string) ([]byte, error) {
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
				return nil, failure()
			}
			key, ok := token.(string)
			if !ok {
				return nil, failure()
			}
			fieldContext = key
			//nolint:errchkjson // Keep the explicit error check required by strict errcheck.
			maskedKey, err := json.Marshal(embargo.Mask(key, scanner.ScanString(key)))
			if err != nil {
				return nil, failure()
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
			return nil, failure()
		}
	}
	closeToken, err := decoder.Token()
	if err != nil {
		return nil, failure()
	}
	closeDelimiter, ok := closeToken.(json.Delim)
	if !ok {
		return nil, failure()
	}
	return append(result, closeDelimiter.String()...), nil
}

// Include the field name so context-based detectors can recognize, for example,
// {"cvv":123}. Translate findings back to value bytes before replacing them.
func maskScalar(scanner *embargo.Scanner, value, context string) string {
	prefix := ""
	if context != "" {
		prefix = context + ": "
	}
	findings := scanner.ScanString(prefix + value)
	spans := make([]embargo.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.End <= len(prefix) {
			continue
		}
		finding.Start = max(0, finding.Start-len(prefix))
		finding.End -= len(prefix)
		spans = append(spans, finding)
	}
	return embargo.Mask(value, spans)
}
