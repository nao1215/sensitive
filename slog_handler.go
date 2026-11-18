package embargo

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/nao1215/embargo/internal/saferecord"
)

// NewSlogHandler masks messages, keys, groups and values with scanner before forwarding
// records to next. Any values keep their JSON shape and clean scalars keep their types.
// Each encoded value is limited to 1 MiB and nesting depth 64. Both arguments must be
// non-nil; nil panics.
//
// A record that cannot be masked is replaced by one with the same time and level, a
// fixed message and a withheld_attributes count; no original field survives. See the
// [logging guide] for value handling and error observation.
//
// Pass the sink handler before any attributes are bound to it, and call With and
// WithGroup on the logger built from the result. Attributes already bound with
// next.WithAttrs or next.WithGroup, and fields next adds itself, never pass through
// embargo: they are written unmasked, also beside a withheld diagnostic.
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
	return &slogHandler{next: next, scanner: scanner, base: next, failed: nil, hidden: false, depth: 0, bound: 0, groups: "", operations: nil, redactGroups: false}
}

type slogOperation struct {
	group string
	attrs []slog.Attr
}

type slogHandler struct {
	next         slog.Handler
	base         slog.Handler
	failed       error
	scanner      *Scanner
	groups       string
	operations   []slogOperation
	bound        int
	depth        int
	hidden       bool
	redactGroups bool
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
	crossed := false
	err := h.failed
	if ctx.Err() != nil {
		err = saferecord.ErrCanceled
	}
	if err == nil {
		safe, crossed, err = h.sanitizeRecord(ctx, &record)
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
	next := h.next
	if crossed && !h.redactGroups {
		next = h.rebuildGroups()
	}
	return next.Handle(ctx, safe)
}

// WithAttrs freezes masked attributes for subsequent records.
func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copyOf := *h
	copyOf.bound += len(attrs)
	if h.hidden || h.failed != nil {
		return &copyOf
	}
	safe, crossed, err := h.sanitizeAttrs(attrs)
	copyOf.failed = err
	if err == nil {
		copyOf.operations = append(slices.Clone(h.operations), slogOperation{attrs: safe})
		copyOf.redactGroups = h.redactGroups || crossed
		if copyOf.redactGroups {
			copyOf.next = copyOf.rebuildGroups()
		} else {
			copyOf.next = h.next.WithAttrs(safe)
		}
	}
	return &copyOf
}

// WithGroup retains grouping for safe records; fallback records have no groups.
func (h *slogHandler) WithGroup(name string) slog.Handler {
	if name == "" || h.hidden || h.failed != nil {
		return h
	}
	copyOf := *h
	safe, crossed, err := h.sanitizeAttrs([]slog.Attr{slog.String(name, "")})
	if h.depth >= maxDepth {
		err = saferecord.ErrSizeLimit
	}
	if err != nil {
		copyOf.failed = err
		return &copyOf
	}
	if h.scanner.sensitiveKey(name) {
		attrs := []slog.Attr{slog.String(safe[0].Key, redactionMarker)}
		copyOf.operations = append(slices.Clone(h.operations), slogOperation{attrs: attrs})
		copyOf.next = h.next.WithAttrs(attrs)
		copyOf.hidden = true
	} else {
		copyOf.next = h.next.WithGroup(safe[0].Key)
		copyOf.depth++
		pathGroup := safe[0].Key
		if crossed {
			// Later segments can extend the same detectable path. Keep its scan
			// context even though every emitted group has already been masked.
			pathGroup = name
		}
		copyOf.groups = joinedKey(h.groups, pathGroup)
		copyOf.operations = append(slices.Clone(h.operations), slogOperation{group: safe[0].Key})
	}
	copyOf.redactGroups = h.redactGroups || crossed
	if copyOf.redactGroups {
		copyOf.next = copyOf.rebuildGroups()
	}
	return &copyOf
}

// Replay only frozen attributes; original callbacks are never evaluated twice.
func (h *slogHandler) rebuildGroups() slog.Handler {
	next := h.base
	for _, op := range h.operations {
		if op.group != "" {
			next = next.WithGroup(redactionMarker)
		} else {
			next = next.WithAttrs(op.attrs)
		}
	}
	return next
}

func slogSanitizationError() error { return errors.New("embargo: slog record could not be sanitized") }

func (h *slogHandler) sanitizeRecord(ctx context.Context, record *slog.Record) (safe slog.Record, crossed bool, err error) {
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
		return slog.Record{}, false, err
	}
	safe = slog.NewRecord(record.Time, record.Level, message, record.PC)
	if h.hidden {
		completed = true
		return safe, false, nil
	}
	// Adding every attribute in one call grows the record's storage once.
	var inline [16]slog.Attr
	attrs, pooled := borrowAttrs(inline[:0], record.NumAttrs())
	defer returnAttrs(pooled)
	record.Attrs(func(attr slog.Attr) bool {
		var clean slog.Attr
		var pathHidden bool
		clean, pathHidden, err = h.sanitizeAttr(ctx, attr, h.depth, h.groups)
		crossed = crossed || pathHidden
		if err != nil {
			return false
		}
		attrs = append(attrs, clean)
		return true
	})
	if err == nil {
		safe.AddAttrs(attrs...)
	}
	completed = true
	return safe, crossed, err
}

// Records with more attributes than sanitizeRecord's inline array borrow
// their working slice here; AddAttrs copies it, so it is reused at once.
const maxPooledAttrs = 256

//nolint:gochecknoglobals // One pool of reusable attribute slices for every handler.
var attrPool = sync.Pool{New: func() any { return new([]slog.Attr) }}

// borrowAttrs returns inline when n attributes fit, and otherwise a pooled
// slice with room for n, which the caller passes to returnAttrs.
func borrowAttrs(inline []slog.Attr, n int) (attrs []slog.Attr, pooled *[]slog.Attr) {
	if n <= cap(inline) {
		return inline, nil
	}
	pooled, ok := attrPool.Get().(*[]slog.Attr)
	if !ok {
		pooled = new([]slog.Attr)
	}
	*pooled = slices.Grow((*pooled)[:0], n)
	return *pooled, pooled
}

// returnAttrs clears a pooled slice so the pool keeps no logged values; nil
// means borrowAttrs returned the caller's inline array.
func returnAttrs(attrs *[]slog.Attr) {
	if attrs == nil || cap(*attrs) > maxPooledAttrs {
		return
	}
	clear((*attrs)[:cap(*attrs)])
	*attrs = (*attrs)[:0]
	attrPool.Put(attrs)
}

func (h *slogHandler) sanitizeAttrs(attrs []slog.Attr) (safe []slog.Attr, crossed bool, err error) {
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
		clean, pathHidden, err := h.sanitizeAttr(context.Background(), attr, h.depth, h.groups)
		crossed = crossed || pathHidden
		if err != nil {
			return nil, false, err
		}
		safe = append(safe, clean)
	}
	completed = true
	return safe, crossed, nil
}

// mask scans a message alone; short clean messages, like field keys, repeat
// across records and come from the scanner's cache.
func (h *slogHandler) mask(ctx context.Context, text string) (string, error) {
	scan := eventScanner{scanner: h.scanner, remaining: maxScanBytes}
	result, err := scan.maskCached(ctx, text)
	return result.masked, err
}

func (h *slogHandler) sanitizeAttr(ctx context.Context, attr slog.Attr, depth int, groups string) (slog.Attr, bool, error) {
	const maxDepth = 64
	if ctx.Err() != nil {
		return slog.Attr{}, false, saferecord.ErrCanceled
	}
	if depth > maxDepth {
		return slog.Attr{}, false, saferecord.ErrSizeLimit
	}
	scan := eventScanner{scanner: h.scanner, remaining: maxScanBytes}
	result, err := scan.maskCached(ctx, attr.Key)
	if err != nil {
		return slog.Attr{}, false, err
	}
	key := result.masked
	pathKey := key
	crossed := false
	if groups != "" && attr.Key != "" {
		scan := eventScanner{scanner: h.scanner, remaining: maxScanBytes}
		crossed, err = scan.joinedKeySensitive(ctx, joinedKey(groups, key), len(groups))
		if err != nil {
			return slog.Attr{}, false, err
		}
		if crossed {
			key = redactionMarker
		}
	}
	if ctx.Err() != nil {
		return slog.Attr{}, false, slogSanitizationError()
	}
	if result.sensitive {
		return slog.String(key, redactionMarker), crossed, nil
	}
	value, err := resolveLogValue(ctx, attr.Value)
	if err != nil {
		return slog.Attr{}, false, err
	}
	switch value.Kind() {
	case slog.KindGroup:
		return h.sanitizeGroup(ctx, key, joinedKey(groups, pathKey), value.Group(), depth, crossed)
	case slog.KindAny:
		safe, err := h.sanitizeAny(ctx, key, attr.Key, value.Any())
		return safe, crossed, err
	case slog.KindString, slog.KindBool, slog.KindDuration, slog.KindFloat64, slog.KindInt64, slog.KindTime, slog.KindUint64:
		safe, err := h.sanitizeScalar(ctx, key, attr.Key, value)
		return safe, crossed, err

	case slog.KindLogValuer:
		return slog.Attr{}, false, slogSanitizationError()
	}
	return slog.Attr{}, false, slogSanitizationError()
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
	// Scan byte contents before an encoder can hide them behind base64.
	// Freeze the result so caller mutation and custom slice methods cannot leak.
	_, rawJSON := value.(json.RawMessage)
	rawValue := reflect.ValueOf(value)
	if !rawJSON && rawValue.IsValid() && rawValue.Kind() == reflect.Slice && rawValue.Type().Elem().Kind() == reflect.Uint8 {
		const jsonQuotes, base64Block, rawBlock = 2, 4, 3
		if rawValue.Len() > (maxEventBytes-jsonQuotes)/base64Block*rawBlock {
			return slog.Attr{}, saferecord.ErrSizeLimit
		}
		return h.sanitizeBytes(ctx, key, originalKey, rawValue.Bytes())
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return slog.Attr{}, slogSanitizationError()
	}
	safe, err := h.scanner.maskJSON(ctx, encoded, originalKey, true)
	if err != nil {
		return slog.Attr{}, err
	}
	return slog.Any(key, maskedJSON(safe)), nil
}

// Inspect both standard handlers' scalar representations before retaining a typed value.
// Any values are frozen as masked JSON, so their original TextMarshaler and String
// methods cannot introduce another representation after this boundary.
func (h *slogHandler) sanitizeScalar(ctx context.Context, key, originalKey string, value slog.Value) (slog.Attr, error) {
	var storage [2]string
	representations := storage[:1]
	switch value.Kind() {
	case slog.KindString:
		representations[0] = value.String()
	case slog.KindTime:
		representations = append(storage[:0], value.Time().Format(time.RFC3339Nano), value.Time().Format("2006-01-02T15:04:05.000Z07:00"))
	case slog.KindDuration:
		representations[0] = value.String()
		representations = append(representations, strconv.FormatInt(int64(value.Duration()), 10))
	case slog.KindFloat64:
		representations[0] = value.String()
		encoded, err := json.Marshal(value.Float64())
		if err != nil {
			return slog.Attr{}, slogSanitizationError()
		}
		representations = append(representations, string(encoded))
	case slog.KindBool:
		// The same text as value.String, which allocates for every value.
		representations[0] = strconv.FormatBool(value.Bool())
	case slog.KindInt64:
		representations[0] = strconv.FormatInt(value.Int64(), 10)
	case slog.KindUint64:
		representations[0] = strconv.FormatUint(value.Uint64(), 10)
	case slog.KindAny, slog.KindGroup, slog.KindLogValuer:
		// Other kinds add no scalar encoding here; composites have separate paths.
		representations[0] = value.String()
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

func joinedKey(groups, key string) string {
	if groups == "" {
		return key
	}
	if key == "" {
		return groups
	}
	return groups + "." + key
}

func (h *slogHandler) sanitizeBytes(ctx context.Context, key, originalKey string, raw []byte) (slog.Attr, error) {
	scan := eventScanner{scanner: h.scanner, remaining: maxScanBytes}
	text := string(raw)
	safe, err := scan.maskScalar(ctx, text, originalKey)
	if err != nil {
		return slog.Attr{}, err
	}
	if safe != text {
		return slog.String(key, safe), nil
	}
	//nolint:errchkjson // Keep an explicit error boundary for encoding.
	encoded, err := json.Marshal(raw)
	if err != nil {
		return slog.Attr{}, slogSanitizationError()
	}
	return slog.Any(key, maskedJSON(encoded)), nil
}

func resolveLogValue(ctx context.Context, value slog.Value) (slog.Value, error) {
	const maxLogValues = 100
	// Calling LogValue directly lets the outer boundary discard panic values.
	// Value.Resolve converts panic contents to an error, which could reveal them.
	for count := 0; value.Kind() == slog.KindLogValuer; count++ {
		if ctx.Err() != nil {
			return slog.Value{}, saferecord.ErrCanceled
		}
		if count == maxLogValues {
			return slog.Value{}, saferecord.ErrSizeLimit
		}
		value = value.LogValuer().LogValue()
	}
	return value, nil
}

func (h *slogHandler) sanitizeGroup(ctx context.Context, key, path string, attrs []slog.Attr, depth int, crossed bool) (slog.Attr, bool, error) {
	safe := make([]slog.Attr, 0, len(attrs))
	for _, child := range attrs {
		clean, childCrossed, err := h.sanitizeAttr(ctx, child, depth+1, path)
		crossed = crossed || childCrossed
		if err != nil {
			return slog.Attr{}, false, err
		}
		safe = append(safe, clean)
	}
	if crossed && key != "" {
		key = redactionMarker
	}
	return slog.Attr{Key: key, Value: slog.GroupValue(safe...)}, crossed, nil
}
