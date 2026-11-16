package embargo

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strconv"
	"time"
)

// NewSlogHandler scans messages, keys, groups and values before forwarding to next.
// Both arguments must be non-nil; invalid dependencies panic.
// The supplied scanner controls selection: NewScanner omits unlabelled entropy tokens.
// Supplying a scanner with WithKinds reduces per-event detection work when only known formats matter.
// See https://github.com/nao1215/embargo/blob/main/doc/benchmarks.md for scan costs, excluding encoding.
// Any values keep their encoded JSON shape; errors keep their Error text.
// Clean scalars and record metadata keep their types; WithAttrs freezes values.
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
	return &slogHandler{next: next, scanner: scanner, failed: false, hidden: false, depth: 0}
}

type slogHandler struct {
	next    slog.Handler
	scanner *Scanner
	failed  bool
	hidden  bool
	depth   int
}

// Enabled asks the downstream handler whether this level is enabled.
func (h *slogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return ctx.Err() == nil && h.next.Enabled(ctx, level)
}

// Handle masks a copied record before passing it to the downstream handler.
//
//nolint:gocritic // slog.Handler requires the record by value.
func (h *slogHandler) Handle(ctx context.Context, record slog.Record) error {
	if ctx.Err() != nil || h.failed {
		return slogSanitizationError()
	}
	safe, err := h.sanitizeRecord(ctx, &record)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return slogSanitizationError()
	}
	return h.next.Handle(ctx, safe)
}

// WithAttrs freezes masked attributes for subsequent records.
func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if h.hidden {
		return h
	}
	safe, err := h.sanitizeAttrs(attrs)
	if h.failed || err != nil {
		return &slogHandler{next: h.next, scanner: h.scanner, failed: true, hidden: h.hidden, depth: h.depth}
	}
	return &slogHandler{next: h.next.WithAttrs(safe), scanner: h.scanner, failed: false, hidden: false, depth: h.depth}
}

// WithGroup retains the downstream grouping contract.
func (h *slogHandler) WithGroup(name string) slog.Handler {
	if name == "" || h.hidden {
		return h
	}
	safe, err := h.sanitizeAttrs([]slog.Attr{slog.String(name, "")})
	if h.failed || err != nil || h.depth >= maxDepth {
		return &slogHandler{next: h.next, scanner: h.scanner, failed: true, hidden: h.hidden, depth: h.depth}
	}
	if h.scanner.sensitiveKey(name) {
		return &slogHandler{next: h.next.WithAttrs([]slog.Attr{slog.String(safe[0].Key, redactionMarker)}), scanner: h.scanner, failed: false, hidden: true, depth: h.depth}
	}
	return &slogHandler{next: h.next.WithGroup(safe[0].Key), scanner: h.scanner, failed: false, hidden: false, depth: h.depth + 1}
}

func slogSanitizationError() error { return errors.New("embargo: slog record could not be sanitized") }

func (h *slogHandler) sanitizeRecord(ctx context.Context, record *slog.Record) (safe slog.Record, err error) {
	completed := false
	defer func() {
		if !completed {
			_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
			safe = slog.Record{}
			err = slogSanitizationError()
		}
	}()
	safe = slog.NewRecord(record.Time, record.Level, h.mask(ctx, record.Message), record.PC)
	if h.hidden {
		completed = true
		return safe, nil
	}
	record.Attrs(func(attr slog.Attr) bool {
		var clean slog.Attr
		clean, err = h.sanitizeAttr(ctx, attr, h.depth)
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
		clean, err := h.sanitizeAttr(context.Background(), attr, h.depth)
		if err != nil {
			return nil, err
		}
		safe = append(safe, clean)
	}
	completed = true
	return safe, nil
}

func (h *slogHandler) mask(ctx context.Context, text string) string {
	return Mask(text, h.scanner.scan([]byte(text), ctx.Err))
}

func (h *slogHandler) sanitizeAttr(ctx context.Context, attr slog.Attr, depth int) (slog.Attr, error) {
	const maxDepth = 64
	const maxLogValues = 100
	if ctx.Err() != nil || depth > maxDepth {
		return slog.Attr{}, slogSanitizationError()
	}
	key := h.mask(ctx, attr.Key)
	if ctx.Err() != nil {
		return slog.Attr{}, slogSanitizationError()
	}
	if h.scanner.sensitiveKey(attr.Key) {
		return slog.String(key, redactionMarker), nil
	}
	value := attr.Value
	// Calling LogValue directly lets the outer boundary discard panic values.
	// Value.Resolve converts panic contents to an error, which could reveal them.
	for count := 0; value.Kind() == slog.KindLogValuer; count++ {
		if ctx.Err() != nil || count == maxLogValues {
			return slog.Attr{}, slogSanitizationError()
		}
		value = value.LogValuer().LogValue()
	}
	switch value.Kind() {
	case slog.KindGroup:
		attrs := value.Group()
		safe := make([]slog.Attr, 0, len(attrs))
		for _, child := range attrs {
			clean, err := h.sanitizeAttr(ctx, child, depth+1)
			if err != nil {
				return slog.Attr{}, err
			}
			safe = append(safe, clean)
		}
		return slog.Attr{Key: key, Value: slog.GroupValue(safe...)}, nil
	case slog.KindAny:
		return h.sanitizeAny(ctx, key, attr.Key, value.Any())
	case slog.KindString, slog.KindBool, slog.KindDuration, slog.KindFloat64, slog.KindInt64, slog.KindTime, slog.KindUint64:
		return h.sanitizeScalar(ctx, key, attr.Key, value)

	case slog.KindLogValuer:
		return slog.Attr{}, slogSanitizationError()
	}
	return slog.Attr{}, slogSanitizationError()
}

// JSONHandler uses MarshalJSON. TextHandler quotes the compact JSON bytes;
// String supplies the same JSON text to other fmt-based downstream handlers.
type maskedJSON []byte

// MarshalJSON preserves an already validated masked JSON representation.
func (v maskedJSON) MarshalJSON() ([]byte, error) { return v, nil }

// String passes a previously masked error message to the logger.
func (v maskedJSON) String() string { return string(v) }

func (h *slogHandler) sanitizeAny(ctx context.Context, key, originalKey string, value any) (slog.Attr, error) {
	if errValue, ok := value.(error); ok {
		return h.sanitizeScalar(ctx, key, originalKey, slog.StringValue(errValue.Error()))
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return slog.Attr{}, slogSanitizationError()
	}
	safe, err := h.scanner.maskJSON(ctx, encoded, originalKey)
	if err != nil {
		return slog.Attr{}, slogSanitizationError()
	}
	return slog.Any(key, maskedJSON(safe)), nil
}

// Inspect both standard handlers' scalar representations before retaining a typed value.
// Any values are frozen as masked JSON, so their original TextMarshaler and String
// methods cannot introduce another representation after this boundary.
func (h *slogHandler) sanitizeScalar(ctx context.Context, key, originalKey string, value slog.Value) (slog.Attr, error) {
	representations := []string{value.String()}
	switch value.Kind() { //nolint:exhaustive // Only these kinds have additional standard-handler encodings.
	case slog.KindTime:
		representations = []string{value.Time().Format(time.RFC3339Nano), value.Time().Format("2006-01-02T15:04:05.000Z07:00")}
	case slog.KindDuration:
		representations = append(representations, strconv.FormatInt(int64(value.Duration()), 10))
	case slog.KindFloat64:
		encoded, err := json.Marshal(value.Float64())
		if err != nil {
			return slog.Attr{}, slogSanitizationError()
		}
		representations = append(representations, string(encoded))
	}
	scan := eventScanner{scanner: h.scanner, remaining: maxScanBytes}
	for _, text := range representations {
		masked, err := scan.maskScalar(ctx, text, originalKey)
		if err != nil {
			return slog.Attr{}, slogSanitizationError()
		}
		if masked != text {
			return slog.String(key, masked), nil
		}
	}
	return slog.Attr{Key: key, Value: value}, nil
}
