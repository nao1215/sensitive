package embargootel

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/nao1215/embargo"
)

func maskText(scanner *embargo.Scanner, text string) string {
	return embargo.Mask(text, scanner.ScanString(text))
}

func maskAttributes(scanner *embargo.Scanner, attrs []attribute.KeyValue) ([]attribute.KeyValue, error) {
	result := make([]attribute.KeyValue, 0, len(attrs))
	for _, kv := range attrs {
		input, err := attributeInput(kv.Value, 0)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(map[string]any{string(kv.Key): input})
		if err != nil {
			return nil, err
		}
		masked, err := scanner.MaskJSON(raw)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(masked))
		decoder.UseNumber()
		var fields map[string]any
		if err := decoder.Decode(&fields); err != nil {
			return nil, err
		}
		for key, value := range fields {
			safe, err := attributeValue(scanner, value, kv.Value)
			if err != nil {
				return nil, err
			}
			result = append(result, attribute.KeyValue{Key: attribute.Key(key), Value: safe})
		}
	}
	return result, nil
}

func attributeValue(scanner *embargo.Scanner, value any, original attribute.Value) (attribute.Value, error) {
	switch v := value.(type) {
	case nil:
		return attribute.Value{}, nil
	case string:
		if original.Type() == attribute.BYTESLICE {
			if v == strings.ToValidUTF8(string(original.AsByteSlice()), "\uFFFD") {
				return original, nil
			}
			return attribute.ByteSliceValue([]byte(v)), nil
		}
		return attribute.StringValue(v), nil
	case bool:
		return attribute.BoolValue(v), nil
	case json.Number:
		if original.Type() == attribute.FLOAT64 {
			return original, nil
		}
		if number, err := v.Int64(); err == nil {
			return attribute.Int64Value(number), nil
		}
		number, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return attribute.Value{}, err
		}
		return attribute.Float64Value(number), nil
	case []any:
		return attributeSlice(scanner, v, original)
	case map[string]any:
		fields := make([]attribute.KeyValue, 0, len(v))
		for key, item := range v {
			template := attribute.Value{}
			for _, kv := range original.AsMap() {
				if string(kv.Key) == key || maskText(scanner, string(kv.Key)) == key {
					template = kv.Value
					break
				}
			}
			converted, err := attributeValue(scanner, item, template)
			if err != nil {
				return attribute.Value{}, err
			}
			fields = append(fields, attribute.KeyValue{Key: attribute.Key(key), Value: converted})
		}
		return attribute.MapValue(fields...), nil
	default:
		return attribute.Value{}, errors.New("embargo: unsupported telemetry value")
	}
}

func attributeSlice(scanner *embargo.Scanner, values []any, original attribute.Value) (attribute.Value, error) {
	result := make([]attribute.Value, 0, len(values))
	stringsOnly := original.Type() == attribute.STRINGSLICE
	texts := make([]string, 0, len(values))
	for i, value := range values {
		template := attribute.Value{}
		if items := original.AsSlice(); i < len(items) {
			template = items[i]
		}
		converted, err := attributeValue(scanner, value, template)
		if err != nil {
			return attribute.Value{}, err
		}
		result = append(result, converted)
		if text, ok := value.(string); ok {
			texts = append(texts, text)
		} else {
			stringsOnly = false
		}
	}
	if stringsOnly {
		return attribute.StringSliceValue(texts), nil
	}
	// Unchanged typed scalar slices retain their SDK type; masking may create mixed slices.
	if original.Type() == attribute.INT64SLICE && allType(result, attribute.INT64) {
		return original, nil
	}
	if original.Type() == attribute.BOOLSLICE && allType(result, attribute.BOOL) {
		return original, nil
	}
	if original.Type() == attribute.FLOAT64SLICE && allNumbers(result) {
		return original, nil
	}
	return attribute.SliceValue(result...), nil
}

func allType(values []attribute.Value, kind attribute.Type) bool {
	for _, value := range values {
		if value.Type() != kind {
			return false
		}
	}
	return true
}

func allNumbers(values []attribute.Value) bool {
	for _, value := range values {
		if value.Type() != attribute.INT64 && value.Type() != attribute.FLOAT64 {
			return false
		}
	}
	return true
}

func attributeInput(value attribute.Value, depth int) (any, error) {
	const maxDepth = 64
	if depth >= maxDepth {
		return nil, errors.New("embargo: telemetry nesting limit")
	}
	switch value.Type() { //nolint:exhaustive // Scalars already have a JSON-compatible representation.
	case attribute.BYTESLICE:
		return string(value.AsByteSlice()), nil
	case attribute.MAP:
		result := make(map[string]any)
		for _, kv := range value.AsMap() {
			item, err := attributeInput(kv.Value, depth+1)
			if err != nil {
				return nil, err
			}
			result[string(kv.Key)] = item
		}
		return result, nil
	case attribute.SLICE:
		values := value.AsSlice()
		result := make([]any, len(values))
		for i, item := range values {
			converted, err := attributeInput(item, depth+1)
			if err != nil {
				return nil, err
			}
			result[i] = converted
		}
		return result, nil
	default:
		return value.AsInterface(), nil
	}
}
