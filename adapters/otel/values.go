package embargootel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/saferecord"
)

func maskText(ctx context.Context, scanner *embargo.Scanner, text string) (string, error) {
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(text); err != nil {
		return "", err
	}
	masked, err := scanner.MaskJSONContext(ctx, encoded.Bytes())
	if err != nil {
		return "", err
	}
	var safe string
	if err := json.Unmarshal(masked, &safe); err != nil {
		return "", err
	}
	return safe, nil
}

func maskTextFields(ctx context.Context, scanner *embargo.Scanner, fields ...*string) error {
	for _, field := range fields {
		safe, err := maskText(ctx, scanner, *field)
		if err != nil {
			return err
		}
		*field = safe
	}
	return nil
}

func maskAttributes(ctx context.Context, scanner *embargo.Scanner, attrs []attribute.KeyValue) ([]attribute.KeyValue, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	result := make([]attribute.KeyValue, 0, len(attrs))
	for _, kv := range attrs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		input, err := attributeInput(ctx, kv.Value, 0)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(map[string]any{string(kv.Key): input})
		if err != nil {
			return nil, err
		}
		masked, err := scanner.MaskJSONContext(ctx, raw)
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
			safe, err := attributeValue(ctx, scanner, value, kv.Value)
			if err != nil {
				return nil, err
			}
			result = append(result, attribute.KeyValue{Key: attribute.Key(key), Value: safe})
		}
	}
	return result, nil
}

func attributeValue(ctx context.Context, scanner *embargo.Scanner, value any, original attribute.Value) (attribute.Value, error) {
	if ctx.Err() != nil {
		return attribute.Value{}, ctx.Err()
	}
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
			number, err := v.Float64()
			return attribute.Float64Value(number), err
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
		return attributeSlice(ctx, scanner, v, original)
	case map[string]any:
		return attributeMap(ctx, scanner, v, original)
	default:
		return attribute.Value{}, errors.New("embargo: unsupported telemetry value")
	}
}

func attributeMap(ctx context.Context, scanner *embargo.Scanner, values map[string]any, original attribute.Value) (attribute.Value, error) {
	templates := make(map[string]attribute.Value)
	for _, kv := range original.AsMap() {
		maskedKey, err := maskText(ctx, scanner, string(kv.Key))
		if err != nil {
			return attribute.Value{}, err
		}
		for _, key := range []string{string(kv.Key), maskedKey} {
			if _, exists := templates[key]; !exists {
				templates[key] = kv.Value
			}
		}
	}
	fields := make([]attribute.KeyValue, 0, len(values))
	for key, item := range values {
		converted, err := attributeValue(ctx, scanner, item, templates[key])
		if err != nil {
			return attribute.Value{}, err
		}
		fields = append(fields, attribute.KeyValue{Key: attribute.Key(key), Value: converted})
	}
	return attribute.MapValue(fields...), nil
}

func attributeSlice(ctx context.Context, scanner *embargo.Scanner, values []any, original attribute.Value) (attribute.Value, error) {
	result := make([]attribute.Value, 0, len(values))
	stringsOnly := original.Type() == attribute.STRINGSLICE
	texts := make([]string, 0, len(values))
	items := original.AsSlice()
	for i, value := range values {
		template := attribute.Value{}
		if i < len(items) {
			template = items[i]
		}
		converted, err := attributeValue(ctx, scanner, value, template)
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
	// Rebuild typed slices only from sanitized values; colliding keys can select another template.
	if original.Type() == attribute.INT64SLICE && allType(result, attribute.INT64) {
		numbers := make([]int64, len(result))
		for i, item := range result {
			numbers[i] = item.AsInt64()
		}
		return attribute.Int64SliceValue(numbers), nil
	}
	if original.Type() == attribute.BOOLSLICE && allType(result, attribute.BOOL) {
		flags := make([]bool, len(result))
		for i, item := range result {
			flags[i] = item.AsBool()
		}
		return attribute.BoolSliceValue(flags), nil
	}
	if original.Type() == attribute.FLOAT64SLICE && allNumbers(result) {
		numbers := make([]float64, len(result))
		for i, item := range result {
			numbers[i] = item.AsFloat64()
			if item.Type() == attribute.INT64 {
				numbers[i] = float64(item.AsInt64())
			}
		}
		return attribute.Float64SliceValue(numbers), nil
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

func attributeInput(ctx context.Context, value attribute.Value, depth int) (any, error) {
	const maxDepth = 64
	if ctx.Err() != nil {
		return nil, saferecord.ErrCanceled
	}
	if depth >= maxDepth {
		return nil, saferecord.ErrSizeLimit
	}
	switch value.Type() { //nolint:exhaustive // Scalars already have a JSON-compatible representation.
	case attribute.BYTESLICE:
		return string(value.AsByteSlice()), nil
	case attribute.MAP:
		result := make(map[string]any)
		for _, kv := range value.AsMap() {
			item, err := attributeInput(ctx, kv.Value, depth+1)
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
			converted, err := attributeInput(ctx, item, depth+1)
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
