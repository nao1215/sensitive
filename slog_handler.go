package embargo

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strconv"
	"time"

	"github.com/nao1215/embargo/internal/saferecord"
)

// NewSlogHandler scans messages, keys, groups and values before forwarding to next.
// Both arguments must be non-nil; invalid dependencies panic.
// The supplied scanner controls selection: NewScanner omits unlabelled entropy tokens.
// Supplying a scanner with WithKinds reduces per-event detection work when only known formats matter.
// See https://github.com/nao1215/embargo/blob/main/doc/benchmarks.md for scan costs, excluding encoding.
// Any values keep their encoded JSON shape; errors keep their Error text.
// Clean scalars and record metadata keep their types; WithAttrs freezes values.
//
// Masking errors, size limits and cancellation emit a withheld record with the
// same time and level, a fixed reason and withheld_attributes; no original fields
// or groups survive. Handle also returns a fixed error, which slog.Logger ignores.
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
	return &slogHandler{next: next, scanner: scanner, base: next, failed: nil, hidden: false, depth: 0, bound: 0}
}

type slogHandler struct {
	next    slog.Handler
	scanner *Scanner
	base    slog.Handler
	failed  error
	bound   int
	hidden  bool
	depth   int
}

// Enabled asks the downstream handler whether this level is enabled.
func (h *slogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if ctx.Err() != nil {
		ctx = context.WithoutCancel(ctx)
	}
	return h.next.Enabled(ctx, level)
}

// Handle masks a copied record before passing it to the downstream handler.
//
//nolint:gocritic // slog.Handler requires the record by value.
func (h *slogHandler) Handle(ctx context.Context, record slog.Record) error {
	var safe slog.Record
	err := h.failed
	if ctx.Err() != nil {
		err = saferecord.ErrCanceled
	}
	if err == nil {
		safe, err = h.sanitizeRecord(ctx, &record)
	}
	if ctx.Err() != nil {
		err = saferecord.ErrCanceled
	}
	if err != nil {
		sinkErr := saferecord.Slog(ctx, h.base, record.Time, record.Level, h.bound+record.NumAttrs(), saferecord.Reason(ctx, err))
		if sinkErr != nil {
			return errors.Join(slogSanitizationError(), sinkErr)
		}
		return slogSanitizationError()
	}
	return h.next.Handle(ctx, safe)
}

// WithAttrs freezes masked attributes for subsequent records.
func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copyOf := *h
	copyOf.bound += len(attrs)
	if h.hidden || h.failed != nil {
		return &copyOf
	}
	safe, err := h.sanitizeAttrs(attrs)
	copyOf.failed = err
	if err == nil {
		copyOf.next = h.next.WithAttrs(safe)
	}
	return &copyOf
}

// WithGroup retains grouping for safe records; fallback records have no groups.
func (h *slogHandler) WithGroup(name string) slog.Handler {
	if name == "" || h.hidden || h.failed != nil {
		return h
	}
	copyOf := *h
	safe, err := h.sanitizeAttrs([]slog.Attr{slog.String(name, "")})
	if h.depth >= maxDepth {
		err = saferecord.ErrSizeLimit
	}
	if err != nil {
		copyOf.failed = err
		return &copyOf
	}
	if h.scanner.sensitiveKey(name) {
		copyOf.next = h.next.WithAttrs([]slog.Attr{slog.String(safe[0].Key, redactionMarker)})
		copyOf.hidden = true
	} else {
		copyOf.next = h.next.WithGroup(safe[0].Key)
		copyOf.depth++
	}
	return &copyOf
}

func slogSanitizationError() error { return errors.New("embargo: slog record could not be sanitized") }

func (h *slogHandler) sanitizeRecord(ctx context.Context, record *slog.Record) (safe slog.Record, err error) {
	completed := false
	defer func() {
		if !completed {
			_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
			safe = slog.Record{}
			if err == nil {
				err = saferecord.ErrMasking
			}
		}
	}()
	message, err := h.mask(ctx, record.Message)
	if err != nil {
		return slog.Record{}, err
	}
	safe = slog.NewRecord(record.Time, record.Level, message, record.PC)
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
			if err == nil {
				err = saferecord.ErrMasking
			}
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

func (h *slogHandler) mask(ctx context.Context, text string) (string, error) {
	scan := eventScanner{scanner: h.scanner, remaining: maxScanBytes}
	return scan.maskScalar(ctx, text, "")
}

func (h *slogHandler) sanitizeAttr(ctx context.Context, attr slog.Attr, depth int) (slog.Attr, error) {
	const maxDepth = 64
	const maxLogValues = 100
	if ctx.Err() != nil {
		return slog.Attr{}, saferecord.ErrCanceled
	}
	if depth > maxDepth {
		return slog.Attr{}, saferecord.ErrSizeLimit
	}
	key, err := h.mask(ctx, attr.Key)
	if err != nil {
		return slog.Attr{}, err
	}
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
		if ctx.Err() != nil {
			return slog.Attr{}, saferecord.ErrCanceled
		}
		if count == maxLogValues {
			return slog.Attr{}, saferecord.ErrSizeLimit
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
	// Plain byte slices have a known base64 size and no user marshaler to invoke.
	// Reject before encoding; arbitrary MarshalJSON implementations remain unbounded.
	const jsonQuotes, base64Block, rawBlock = 2, 4, 3
	if raw, ok := value.([]byte); ok && len(raw) > (maxEventBytes-jsonQuotes)/base64Block*rawBlock {
		return slog.Attr{}, saferecord.ErrSizeLimit
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return slog.Attr{}, slogSanitizationError()
	}
	safe, err := h.scanner.maskJSON(ctx, encoded, originalKey)
	if err != nil {
		return slog.Attr{}, err
	}
	return slog.Any(key, maskedJSON(safe)), nil
}

// Inspect both standard handlers' scalar representations before retaining a typed value.
// Any values are frozen as masked JSON, so their original TextMarshaler and String
// methods cannot introduce another representation after this boundary.
func (h *slogHandler) sanitizeScalar(ctx context.Context, key, originalKey string, value slog.Value) (slog.Attr, error) {
	representations := []string{value.String()}
	switch value.Kind() {
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
	case slog.KindAny, slog.KindBool, slog.KindGroup, slog.KindInt64, slog.KindLogValuer, slog.KindString, slog.KindUint64:
		// Other kinds add no scalar encoding here; composites have separate paths.
	}
	scan := eventScanner{scanner: h.scanner, remaining: maxScanBytes}
	for _, text := range representations {
		masked, err := scan.maskScalar(ctx, text, originalKey)
		if err != nil {
			return slog.Attr{}, err
		}
		if masked != text {
			return slog.String(key, masked), nil
		}
	}
	return slog.Attr{Key: key, Value: value}, nil
}
