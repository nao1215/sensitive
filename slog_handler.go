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
	decision, crossed, prefixCrossed, err := h.groupKey(name)
	if h.depth >= maxDepth {
		err = saferecord.ErrSizeLimit
	}
	if err != nil {
		copyOf.failed = err
		return &copyOf
	}
	key := decision.masked
	if crossed {
		key = redactionMarker
	}
	if decision.sensitive {
		attrs := []slog.Attr{slog.String(key, redactionMarker)}
		copyOf.operations = append(slices.Clone(h.operations), slogOperation{attrs: attrs})
		copyOf.next = h.next.WithAttrs(attrs)
		copyOf.hidden = true
	} else {
		copyOf.next = h.next.WithGroup(key)
		copyOf.depth++
		copyOf.groups = joinedKey(h.groups, pathKey(decision))
		copyOf.operations = append(slices.Clone(h.operations), slogOperation{group: key})
	}
	copyOf.redactGroups = h.redactGroups || prefixCrossed
	if copyOf.redactGroups {
		copyOf.next = copyOf.rebuildGroups()
	}
	return &copyOf
}

// groupKey decides a WithGroup name as a member key under the bound groups.
func (h *slogHandler) groupKey(name string) (decision memberKey, crossed, prefixCrossed bool, err error) {
	completed := false
	defer func() {
		if !completed {
			_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
			if err == nil {
				err = saferecord.ErrMasking
			}
		}
	}()
	policy := newFieldPolicy(h.scanner, h.groups)
	defer policy.release()
	decision, err = policy.member(context.Background(), name)
	if err != nil {
		return memberKey{}, false, false, err
	}
	crossed = policy.leave()
	completed = true
	return decision, crossed, policy.prefixCrossed, nil
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
	members := slogMembers{handler: h, policy: newFieldPolicy(h.scanner, h.groups), pair: namedPair[int]{}}
	defer members.policy.release()
	record.Attrs(func(attr slog.Attr) bool {
		var clean slog.Attr
		clean, err = members.add(ctx, attr, h.depth, len(attrs))
		attrs = append(attrs, clean)
		return err == nil
	})
	if err == nil {
		members.finish(attrs)
		safe.AddAttrs(attrs...)
	}
	completed = true
	return safe, members.policy.prefixCrossed, err
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
		panic("embargo: invalid attribute pool value")
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
	members := slogMembers{handler: h, policy: newFieldPolicy(h.scanner, h.groups), pair: namedPair[int]{}}
	defer members.policy.release()
	safe = make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		clean, err := members.add(context.Background(), attr, h.depth, len(safe))
		if err != nil {
			return nil, false, err
		}
		safe = append(safe, clean)
	}
	members.finish(safe)
	completed = true
	return safe, members.policy.prefixCrossed, nil
}

// slogMembers sanitizes the attributes of one record, WithAttrs call or
// group as members of one object under the handler's bound groups.
type slogMembers struct {
	handler *slogHandler
	policy  fieldPolicy
	pair    namedPair[int]
}

// add sanitizes one top-level attribute, which the caller stores at index.
// The record's attributes share one scan budget, as one encoded event does.
func (m *slogMembers) add(ctx context.Context, attr slog.Attr, depth, index int) (slog.Attr, error) {
	clean, err := m.handler.sanitizeAttr(ctx, &m.policy, attr, depth)
	if err != nil {
		return slog.Attr{}, err
	}
	observeSlogPair(&m.policy, &m.pair, attr.Key, clean.Value, index)
	return clean, nil
}

// finish writes the marker for the pair values among attrs.
func (m *slogMembers) finish(attrs []slog.Attr) {
	m.pair.hidden(func(i int) { attrs[i].Value = slog.StringValue(redactionMarker) })
}

// observeSlogPair records a sanitized member of a name and value pair.
func observeSlogPair(policy *fieldPolicy, pair *namedPair[int], key string, value slog.Value, index int) {
	switch namedValueField(key) {
	case pairName:
		if value.Kind() == slog.KindString {
			pair.name(policy, value.String())
		}
	case pairValue:
		pair.value(slogShape(value), index)
	case pairNone:
	}
}

// slogShape classifies a sanitized slog value as a pair value member.
func slogShape(value slog.Value) valueShape {
	switch value.Kind() { //nolint:exhaustive // Other kinds are numbers, booleans, times and durations.
	case slog.KindString:
		if value.String() != "" {
			return shapeText
		}
	case slog.KindGroup:
		return shapeContainer
	case slog.KindAny:
		if encoded, ok := value.Any().(maskedJSON); ok {
			return jsonValueShape(encoded)
		}
	}
	return shapeOther
}

// mask scans a message alone; short clean messages, like field keys, repeat
// across records and come from the scanner's cache.
func (h *slogHandler) mask(ctx context.Context, text string) (string, error) {
	scan := eventScanner{scanner: h.scanner, spare: nil, remaining: maxScanBytes}
	masked, _, err := scan.maskCached(ctx, text)
	scan.release()
	return masked, err
}

func (h *slogHandler) sanitizeAttr(ctx context.Context, policy *fieldPolicy, attr slog.Attr, depth int) (slog.Attr, error) {
	if ctx.Err() != nil {
		return slog.Attr{}, saferecord.ErrCanceled
	}
	if depth > maxDepth {
		return slog.Attr{}, saferecord.ErrSizeLimit
	}
	decision, err := policy.member(ctx, attr.Key)
	if err != nil {
		return slog.Attr{}, err
	}
	value := slog.StringValue(redactionMarker)
	if !decision.sensitive {
		if value, err = h.sanitizeValue(ctx, policy, decision.key, attr.Value, depth); err != nil {
			return slog.Attr{}, err
		}
	}
	key := decision.masked
	if policy.leave() {
		key = redactionMarker
	}
	return slog.Attr{Key: key, Value: value}, nil
}

func (h *slogHandler) sanitizeValue(ctx context.Context, policy *fieldPolicy, key string, value slog.Value, depth int) (slog.Value, error) {
	value, err := resolveLogValue(ctx, value)
	if err != nil {
		return slog.Value{}, err
	}
	switch value.Kind() {
	case slog.KindGroup:
		return h.sanitizeGroup(ctx, policy, value.Group(), depth)
	case slog.KindAny:
		return h.sanitizeAny(ctx, policy, key, value.Any())
	case slog.KindString, slog.KindBool, slog.KindDuration, slog.KindFloat64, slog.KindInt64, slog.KindTime, slog.KindUint64:
		return sanitizeScalar(ctx, policy, key, value)
	case slog.KindLogValuer:
	}
	return slog.Value{}, slogSanitizationError()
}

// JSONHandler uses MarshalJSON. TextHandler quotes the compact JSON bytes;
// String supplies the same JSON text to other fmt-based downstream handlers.
type maskedJSON []byte

// MarshalJSON preserves an already validated masked JSON representation.
func (v maskedJSON) MarshalJSON() ([]byte, error) { return v, nil }

// String passes a previously masked error message to the logger.
func (v maskedJSON) String() string { return string(v) }

// sanitizeAny masks an Any value as a JSON document that continues the
// policy's key path, so its members follow the same rules as groups.
func (h *slogHandler) sanitizeAny(ctx context.Context, policy *fieldPolicy, key string, value any) (slog.Value, error) {
	if errValue, ok := value.(error); ok {
		return sanitizeScalar(ctx, policy, key, slog.StringValue(errValue.Error()))
	}
	// Scan byte contents before an encoder can hide them behind base64.
	// Freeze the result so caller mutation and custom slice methods cannot leak.
	_, rawJSON := value.(json.RawMessage)
	rawValue := reflect.ValueOf(value)
	if !rawJSON && rawValue.IsValid() && rawValue.Kind() == reflect.Slice && rawValue.Type().Elem().Kind() == reflect.Uint8 {
		const jsonQuotes, base64Block, rawBlock = 2, 4, 3
		if rawValue.Len() > (maxEventBytes-jsonQuotes)/base64Block*rawBlock {
			return slog.Value{}, saferecord.ErrSizeLimit
		}
		return sanitizeBytes(ctx, policy, key, rawValue.Bytes())
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return slog.Value{}, slogSanitizationError()
	}
	safe, err := policy.maskJSON(ctx, encoded, key, true)
	if err != nil {
		return slog.Value{}, err
	}
	return slog.AnyValue(maskedJSON(safe)), nil
}

// Inspect both standard handlers' scalar representations before retaining a typed value.
// Any values are frozen as masked JSON, so their original TextMarshaler and String
// methods cannot introduce another representation after this boundary.
func sanitizeScalar(ctx context.Context, policy *fieldPolicy, key string, value slog.Value) (slog.Value, error) {
	var storage [2]string
	representations := storage[:1]
	switch value.Kind() {
	case slog.KindString, slog.KindAny, slog.KindGroup, slog.KindLogValuer:
		// Composites have separate paths and never reach this switch.
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
			return slog.Value{}, slogSanitizationError()
		}
		representations = append(representations, string(encoded))
	case slog.KindBool:
		// The same text as value.String, which allocates for every value.
		representations[0] = strconv.FormatBool(value.Bool())
	case slog.KindInt64:
		representations[0] = strconv.FormatInt(value.Int64(), 10)
	case slog.KindUint64:
		representations[0] = strconv.FormatUint(value.Uint64(), 10)
	}
	for _, text := range representations {
		masked, err := policy.scan.maskScalar(ctx, text, key)
		if err != nil {
			return slog.Value{}, err
		}
		if masked != text {
			return slog.StringValue(masked), nil
		}
	}
	return value, nil
}

func sanitizeBytes(ctx context.Context, policy *fieldPolicy, key string, raw []byte) (slog.Value, error) {
	text := string(raw)
	safe, err := policy.scan.maskScalar(ctx, text, key)
	if err != nil {
		return slog.Value{}, err
	}
	if safe != text {
		return slog.StringValue(safe), nil
	}
	//nolint:errchkjson // Keep an explicit error boundary for encoding.
	encoded, err := json.Marshal(raw)
	if err != nil {
		return slog.Value{}, slogSanitizationError()
	}
	return slog.AnyValue(maskedJSON(encoded)), nil
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

// sanitizeGroup masks a group's attributes as members of one object.
func (h *slogHandler) sanitizeGroup(ctx context.Context, policy *fieldPolicy, attrs []slog.Attr, depth int) (slog.Value, error) {
	safe := make([]slog.Attr, 0, len(attrs))
	var pair namedPair[int]
	for _, child := range attrs {
		clean, err := h.sanitizeAttr(ctx, policy, child, depth+1)
		if err != nil {
			return slog.Value{}, err
		}
		safe = append(safe, clean)
		observeSlogPair(policy, &pair, child.Key, clean.Value, len(safe)-1)
	}
	pair.hidden(func(i int) { safe[i].Value = slog.StringValue(redactionMarker) })
	return slog.GroupValue(safe...), nil
}
