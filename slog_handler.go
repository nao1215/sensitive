package embargo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"
)

// NewSlogHandler scans messages, keys, groups and values before forwarding to next.
// Both arguments must be non-nil; invalid dependencies panic.
// Any and error values become scanned strings, while clean scalars and record
// metadata keep their types; WithAttrs freezes sanitized values.
//
// Scanner or normalization failures drop the record and return a fixed error.
// Values added by downstream handlers need their own output check.
// See the [logging guide] for value handling and error observation.
//
// [logging guide]: https://github.com/nao1215/embargo/blob/main/doc/logging.md
func NewSlogHandler(next slog.Handler, scanner *Scanner) slog.Handler {
	if next == nil {
		panic("embargo: nil slog handler")
	}
	value := reflect.ValueOf(next)
	switch value.Kind() { //nolint:exhaustive // Only nil-capable implementation kinds need IsNil.
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			panic("embargo: nil slog handler")
		}
	}
	if scanner == nil {
		panic("embargo: nil scanner")
	}
	return &slogHandler{next: next, scanner: scanner, failed: false}
}

type slogHandler struct {
	next    slog.Handler
	scanner *Scanner
	failed  bool
}

func (h *slogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

//nolint:gocritic // slog.Handler requires the record by value.
func (h *slogHandler) Handle(ctx context.Context, record slog.Record) error {
	if h.failed {
		return slogSanitizationError()
	}
	safe, err := h.sanitizeRecord(&record)
	if err != nil {
		return err
	}
	return h.next.Handle(ctx, safe)
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	safe, err := h.sanitizeAttrs(attrs)
	if h.failed || err != nil {
		return &slogHandler{next: h.next, scanner: h.scanner, failed: true}
	}
	return &slogHandler{next: h.next.WithAttrs(safe), scanner: h.scanner, failed: false}
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	safe, err := h.sanitizeAttrs([]slog.Attr{slog.String(name, "")})
	if h.failed || err != nil {
		return &slogHandler{next: h.next, scanner: h.scanner, failed: true}
	}
	return &slogHandler{next: h.next.WithGroup(safe[0].Key), scanner: h.scanner, failed: false}
}

func slogSanitizationError() error { return errors.New("embargo: slog record could not be sanitized") }

func (h *slogHandler) sanitizeRecord(record *slog.Record) (safe slog.Record, err error) {
	completed := false
	defer func() {
		if !completed {
			_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
			safe = slog.Record{}
			err = slogSanitizationError()
		}
	}()
	safe = slog.NewRecord(record.Time, record.Level, h.mask(record.Message), record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		var clean slog.Attr
		clean, err = h.sanitizeAttr(attr, 0)
		if err != nil {
			return false
		}
		safe.AddAttrs(clean)
		return true
	})
	completed = true
	return safe, err
}

func (h *slogHandler) sanitizeAttrs(attrs []slog.Attr) (safe []slog.Attr, err error) {
	completed := false
	defer func() {
		if !completed {
			_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
			safe = nil
			err = slogSanitizationError()
		}
	}()
	safe = make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		clean, err := h.sanitizeAttr(attr, 0)
		if err != nil {
			return nil, err
		}
		safe = append(safe, clean)
	}
	completed = true
	return safe, nil
}
func (h *slogHandler) mask(text string) string { return Mask(text, h.scanner.ScanString(text)) }

func (h *slogHandler) sanitizeAttr(attr slog.Attr, depth int) (slog.Attr, error) {
	const maxDepth = 64
	const maxLogValues = 100
	if depth > maxDepth {
		return slog.Attr{}, slogSanitizationError()
	}
	value := attr.Value
	// Calling LogValue directly lets the outer boundary discard panic values.
	// Value.Resolve converts panic contents to an error, which could reveal them.
	for count := 0; value.Kind() == slog.KindLogValuer; count++ {
		if count == maxLogValues {
			return slog.Attr{}, slogSanitizationError()
		}
		value = value.LogValuer().LogValue()
	}
	key := h.mask(attr.Key)
	switch value.Kind() {
	case slog.KindGroup:
		attrs := value.Group()
		safe := make([]slog.Attr, 0, len(attrs))
		for _, child := range attrs {
			clean, err := h.sanitizeAttr(child, depth+1)
			if err != nil {
				return slog.Attr{}, err
			}
			safe = append(safe, clean)
		}
		return slog.Attr{Key: key, Value: slog.GroupValue(safe...)}, nil
	case slog.KindAny:
		if value.Any() == nil {
			return slog.Attr{Key: key, Value: value}, nil
		}
		text, err := slogAnyText(value.Any())
		if err != nil {
			return slog.Attr{}, err
		}
		return slog.String(key, h.mask(text)), nil
	case slog.KindString:
		return slog.String(key, h.mask(value.String())), nil
	case slog.KindBool, slog.KindDuration, slog.KindFloat64, slog.KindInt64, slog.KindTime, slog.KindUint64:
		text := value.String()
		if value.Kind() == slog.KindTime {
			text = value.Time().Format(time.RFC3339Nano)
		}
		// JSON uses decimal notation for some floats that Value.String formats as exponents.
		if value.Kind() == slog.KindFloat64 {
			encoded, err := json.Marshal(value.Float64())
			if err != nil {
				return slog.Attr{}, slogSanitizationError()
			}
			if masked := h.mask(string(encoded)); masked != string(encoded) {
				return slog.String(key, masked), nil
			}
		}
		if masked := h.mask(text); masked != text {
			return slog.String(key, masked), nil
		}
		return slog.Attr{Key: key, Value: value}, nil
	case slog.KindLogValuer:
		return slog.Attr{}, slogSanitizationError()
	}
	return slog.Attr{}, slogSanitizationError()
}

func slogAnyText(value any) (string, error) {
	switch v := value.(type) {
	case error:
		return v.Error(), nil
	case fmt.Stringer:
		return v.String(), nil
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", slogSanitizationError()
		}
		return string(encoded), nil
	}
}
