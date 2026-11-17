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
		matches, valid := jsonMatches(data, copiedPath, want)
		return valid && matches == count
	})
}

// jsonMatches counts the JSON or NDJSON documents whose object at path has
// every wanted field. Any invalid document makes the whole input invalid.
func jsonMatches(data []byte, path []string, want map[string]string) (matches int, valid bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	for {
		before := decoder.InputOffset()
		value, err := jsonValue(decoder, 0)
		if errors.Is(err, io.EOF) {
			return matches, len(bytes.TrimSpace(data[before:])) == 0
		}
		if err != nil {
			return 0, false
		}
		if object, ok := jsonAtPath(value, path).(map[string]any); ok && hasFields(object, want) {
			matches++
		}
	}
}

// jsonAtPath follows object keys from value; a non-object along the way
// yields nil, which no field expectation can match.
func jsonAtPath(value any, path []string) any {
	for _, part := range path {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[part]
	}
	return value
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
		return jsonObject(decoder, depth)
	case '[':
		return jsonArray(decoder, depth)
	default:
		return nil, jsonError{}
	}
}

// jsonObject decodes object members after the opening brace, rejecting
// duplicate keys so that a later value cannot shadow an expected field.
func jsonObject(decoder *json.Decoder, depth int) (any, error) {
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
}

// jsonArray validates array elements after the opening bracket without
// retaining them.
func jsonArray(decoder *json.Decoder, depth int) (any, error) {
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
}
