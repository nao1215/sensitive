package embargotest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
)

// ExpectJSON requires count objects at path, in JSON or NDJSON, whose string
// fields equal every entry of fields, such as {"code": "signing_failed"}. It
// checks that the information needed to investigate a failure arrived, not
// only that the secret is absent. Count must be positive and fields nonempty.
// Invalid JSON, duplicate object keys and nesting deeper than 64 fail, even
// outside the selected path.
func (r *Recorder) ExpectJSON(name string, path []string, fields map[string]string, count int) {
	copiedPath := append([]string(nil), path...)
	want := maps.Clone(fields)
	r.Expect(name, func(data []byte) bool {
		if count <= 0 || len(want) == 0 {
			return false
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		matches := 0
		for {
			before := decoder.InputOffset()
			value, err := jsonValue(decoder, 0)
			if errors.Is(err, io.EOF) {
				if len(bytes.TrimSpace(data[before:])) != 0 {
					return false
				}
				break
			}
			if err != nil {
				return false
			}
			for _, part := range copiedPath {
				object, ok := value.(map[string]any)
				if !ok {
					value = nil
					break
				}
				value = object[part]
			}
			if object, ok := value.(map[string]any); ok && hasFields(object, want) {
				matches++
			}
		}
		return matches == count
	})
}

func hasFields(object map[string]any, want map[string]string) bool {
	for key, value := range want {
		if got, ok := object[key].(string); !ok || got != value {
			return false
		}
	}
	return true
}

type jsonError struct{}

// Error reports invalid JSON without including the rejected bytes.
func (jsonError) Error() string { return "embargotest: invalid JSON record" }

func jsonValue(decoder *json.Decoder, depth int) (any, error) {
	//nolint:mnd // This bound follows HTTP sniffing, JSON nesting, metadata encoding, or child-name limits.
	if depth > 64 {
		return nil, jsonError{}
	}
	value, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := value.(json.Delim)
	if !ok {
		return value, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := token.(string)
			if !ok {
				return nil, jsonError{}
			}
			if _, exists := object[key]; exists {
				return nil, jsonError{}
			}
			child, err := jsonValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = child
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		for decoder.More() {
			if _, err := jsonValue(decoder, depth+1); err != nil {
				return nil, err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}

		//nolint:nilnil // A validated array is consumed but cannot satisfy object-field expectations.
		return nil, nil
	default:
		return nil, jsonError{}
	}
}
