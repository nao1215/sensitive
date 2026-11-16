package embargo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

const (
	canceledReason = "canceled"
	maskingReason  = "masking error"
	sizeReason     = "size limit"
)

type canaryDetector string

func (d canaryDetector) Scan(data []byte) []embargo.Finding {
	var findings []embargo.Finding
	for offset := 0; offset < len(data); {
		start := strings.Index(string(data[offset:]), string(d))
		if start < 0 {
			break
		}
		start += offset
		end := start + len(d)
		findings = append(findings, embargo.Finding{Kind: "canary", Start: start, End: end, Confidence: 1})
		offset = end
	}
	return findings
}

type changingString struct {
	calls *atomic.Int64
	text  string
}

func (s changingString) MarshalJSON() ([]byte, error) { s.calls.Add(1); return json.Marshal(s.text) }

type secretLogValue string

func (s secretLogValue) LogValue() slog.Value { return slog.StringValue(string(s)) }

type cyclicLogValue struct{}

func (cyclicLogValue) LogValue() slog.Value { return slog.AnyValue(cyclicLogValue{}) }

type panicNilLogValue struct{}

func (panicNilLogValue) LogValue() slog.Value { panic(nil) } //nolint:govet // Exercise panic(nil) under both runtime compatibility settings.

type panicLogValue struct{}

func (panicLogValue) LogValue() slog.Value { panic("synthetic panic must not appear") }

type panicString struct{}

func (panicString) MarshalJSON() ([]byte, error) { panic("synthetic panic must not appear") }

type panicDetector struct{}

func (panicDetector) Scan([]byte) []embargo.Finding { panic("synthetic panic must not appear") }

func TestSlogRealHandlers(t *testing.T) {
	t.Parallel()
	for _, jsonOutput := range []bool{false, true} {
		t.Run(strconv.FormatBool(jsonOutput), func(t *testing.T) {
			t.Parallel()
			recorder := embargotest.New(t)
			canary := string(recorder.Canary())
			scanner := embargo.NewScanner(embargo.WithDetector(canaryDetector(canary)))
			var next slog.Handler = slog.NewTextHandler(recorder.Writer("logs"), nil)
			if jsonOutput {
				next = slog.NewJSONHandler(recorder.Writer("logs"), nil)
			}
			logger := slog.New(embargo.NewSlogHandler(next, scanner))
			var calls atomic.Int64
			attached := logger.With("attached", changingString{calls: &calls, text: canary})
			grouped := attached.WithGroup(canary)
			for range 2 {
				grouped.Info("notify alice@example.com "+canary,
					canary, canary,
					"group", slog.GroupValue(slog.String("card", "4532015112830366"), slog.Any("error", errors.New(canary))),
					"float", float64(4532015112830366),
					"int", int64(4532015112830366),
					"uint", uint64(4532015112830366),
					"value", secretLogValue(canary),
					"object", map[string]string{"token": canary},
				)
			}
			if calls.Load() != 1 {
				t.Fatal("WithAttrs retained an opaque mutable value")
			}
			recorder.Expect("logs", func(data []byte) bool {
				return bytes.Count(data, []byte("[REDACTED]")) >= 20 && !bytes.Contains(data, []byte("alice@example.com"))
			})
			recorder.Check()
		})
	}
}

type inspectingHandler struct {
	err        error
	ctxMatches func(context.Context) bool
	group      string
	record     slog.Record
	attrs      []slog.Attr
	handled    int
	contextOK  bool
	enabled    bool
}

func (h *inspectingHandler) Enabled(context.Context, slog.Level) bool { return h.enabled }

//nolint:gocritic // Implement the real slog.Handler contract for delegation checks.
func (h *inspectingHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.ctxMatches != nil {
		h.contextOK = h.ctxMatches(ctx)
	}
	h.record = r
	h.handled++
	return h.err
}
func (h *inspectingHandler) WithAttrs(attrs []slog.Attr) slog.Handler { h.attrs = attrs; return h }
func (h *inspectingHandler) WithGroup(name string) slog.Handler       { h.group = name; return h }

func TestSlogPreservesCleanRecord(t *testing.T) {
	t.Parallel()
	downstream := errors.New("downstream rejected")
	next := &inspectingHandler{enabled: true, err: downstream, ctxMatches: func(ctx context.Context) bool { return ctx == t.Context() }}
	handler := embargo.NewSlogHandler(next, embargo.NewScanner())
	if !handler.Enabled(t.Context(), slog.LevelInfo) {
		t.Fatal("Enabled not delegated")
	}
	stamp := time.Unix(1, 2)
	record := slog.NewRecord(stamp, slog.LevelWarn, "accepted", 123)
	record.AddAttrs(slog.Int("count", 7), slog.Bool("enabled", true), slog.Duration("elapsed", time.Second), slog.Time("when", stamp), slog.Any("nil", nil))
	if !errors.Is(handler.Handle(t.Context(), record), downstream) {
		t.Fatal("downstream error changed")
	}
	if !next.contextOK || next.record.Time != record.Time || next.record.PC != record.PC || next.record.Level != record.Level || record.Message != "accepted" {
		t.Fatal("record metadata changed")
	}
	var kinds []slog.Kind
	next.record.Attrs(func(a slog.Attr) bool { kinds = append(kinds, a.Value.Kind()); return true })
	if fmt.Sprint(kinds) != "[Int64 Bool Duration Time Any]" {
		t.Fatal("clean scalar types changed")
	}
}

func TestSlogRejectsInvalidConstruction(t *testing.T) {
	t.Parallel()
	for _, next := range []slog.Handler{nil, (*inspectingHandler)(nil)} {
		func() {
			defer func() {
				if recover() != "embargo: nil slog handler" {
					t.Error("nil handler contract")
				}
			}()
			embargo.NewSlogHandler(next, embargo.NewScanner())
		}()
	}
	func() {
		defer func() {
			if recover() != "embargo: nil scanner" {
				t.Error("nil scanner contract")
			}
		}()
		embargo.NewSlogHandler(&inspectingHandler{}, nil)
	}()
}

func TestSlogSuppressesNormalizationFailures(t *testing.T) {
	t.Parallel()
	for _, value := range []any{panicNilLogValue{}, panicLogValue{}, panicString{}, cyclicLogValue{}, make(chan int)} {
		for _, attach := range []bool{false, true} {
			next := &inspectingHandler{}
			handler := embargo.NewSlogHandler(next, embargo.NewScanner())
			record := slog.NewRecord(time.Time{}, slog.LevelInfo, "accepted", 0)
			if attach {
				handler = handler.WithAttrs([]slog.Attr{slog.Any("value", value)})
			} else {
				record.AddAttrs(slog.Any("value", value))
			}
			err := handler.Handle(t.Context(), record)
			if err == nil || err.Error() != "embargo: slog record could not be sanitized" || next.handled != 1 {
				t.Fatal("failed normalization did not produce a fallback")
			}
		}
	}
	next := &inspectingHandler{}
	handler := embargo.NewSlogHandler(next, embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(panicDetector{})))
	err := handler.WithGroup("private").Handle(t.Context(), slog.NewRecord(time.Time{}, slog.LevelInfo, "message", 0))
	if err == nil || err.Error() != "embargo: slog record could not be sanitized" || next.handled != 1 {
		t.Fatal("scanner panic reached downstream")
	}
}

func TestSlogGroupsAndConcurrency(t *testing.T) {
	t.Parallel()
	recorder := embargotest.New(t)
	handler := embargo.NewSlogHandler(slog.NewJSONHandler(recorder.Writer("logs"), nil), embargo.NewScanner())
	logger := slog.New(handler.WithGroup("")).WithGroup("public").With("email", "alice@example.com")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { logger.Info("accepted", "nested", slog.GroupValue(slog.String("value", "bob@example.com"))) })
	}
	wg.Wait()
	recorder.Expect("logs", func(data []byte) bool {
		lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
		if len(lines) != 8 {
			return false
		}
		for _, line := range lines {
			var value map[string]json.RawMessage
			if json.Unmarshal(line, &value) != nil || value["public"] == nil {
				return false
			}
		}
		return true
	})
	recorder.Check()
}

func TestSlogNilPanicCompatibility(t *testing.T) {
	t.Setenv("GODEBUG", "panicnil=1")
	for _, attached := range []bool{false, true} {
		next := &inspectingHandler{}
		handler := embargo.NewSlogHandler(next, embargo.NewScanner())
		record := slog.NewRecord(time.Time{}, slog.LevelInfo, "accepted", 0)
		if attached {
			handler = handler.WithAttrs([]slog.Attr{slog.Any("value", panicNilLogValue{})})
		} else {
			record.AddAttrs(slog.Any("value", panicNilLogValue{}))
		}
		if err := handler.Handle(t.Context(), record); err == nil || next.handled != 1 {
			t.Fatal("nil panic reached downstream")
		}
	}
}

// TestSlogOriginalKeyContext ports original-key scalar context and the review's five binding variants.
func TestSlogOriginalKeyContext(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		value any
		key   string
	}{{731, "cvv"}, {"opaque-client-value", "client_secret"}, {12345678, "bank account"}, {"12/29", "expiry"}} {
		for _, mode := range []string{"direct", "WithAttrs", "group", "LogValuer", "error", "any scalar"} {
			t.Run(fixture.key+"/"+mode, func(t *testing.T) {
				t.Parallel()
				var out bytes.Buffer
				logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: omitRecordTime}), embargo.NewScanner()))
				value := fmt.Sprint(fixture.value)
				switch mode {
				case "direct":
					logger.Info("event", fixture.key, fixture.value)
				case "WithAttrs":
					logger.With(fixture.key, fixture.value).Info("event")
				case "group":
					logger.Info("event", slog.Group("request", fixture.key, fixture.value))
				case "LogValuer":
					logger.Info("event", fixture.key, secretLogValue(value))
				case "error":
					logger.Info("event", fixture.key, errors.New(value))
				case "any scalar":
					logger.Info("event", fixture.key, json.RawMessage(strconv.Quote(value)))
				}
				if out.Len() == 0 || strings.Contains(out.String(), value) || !strings.Contains(out.String(), "[REDACTED]") {
					t.Fatalf("context lost: %s", out.String())
				}
			})
		}
	}
}

// Both standard handlers must be safe even when only the other rendering matches.
func TestSlogEncodedRepresentations(t *testing.T) {
	t.Parallel()
	instant := time.Date(2026, time.November, 16, 12, 34, 56, 123456789, time.FixedZone("fixture", 3600))
	for _, fixture := range []struct {
		name  string
		value slog.Value
		text  string
	}{
		{"duration integer", slog.DurationValue(time.Duration(4111111111111111)), "4111111111111111"},
		{"duration text", slog.DurationValue(time.Second), "1s"},
		{"float decimal", slog.Float64Value(4111111111111111), "4111111111111111"},
		{"float exponent", slog.Float64Value(4111111111111111), "4.111111111111111e+15"},
		{"time JSON", slog.TimeValue(instant), "2026-11-16T12:34:56.123456789+01:00"},
		{"time text", slog.TimeValue(instant), "2026-11-16T12:34:56.123+01:00"},
		{"int", slog.Int64Value(731), "731"},
		{"uint", slog.Uint64Value(731), "731"},
		{"bool", slog.BoolValue(true), "true"},
		{"string", slog.StringValue("fixture-value"), "fixture-value"},
	} {
		for _, jsonOutput := range []bool{false, true} {
			t.Run(fixture.name+"/"+strconv.FormatBool(jsonOutput), func(t *testing.T) {
				t.Parallel()
				var out bytes.Buffer
				var next slog.Handler = slog.NewTextHandler(&out, nil)
				if jsonOutput {
					next = slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: omitRecordTime})
				}
				scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(canaryDetector(fixture.text)))
				h := embargo.NewSlogHandler(next, scanner)
				r := slog.NewRecord(time.Time{}, slog.LevelInfo, "event", 0)
				r.AddAttrs(slog.Attr{Key: "value", Value: fixture.value})
				if err := h.Handle(t.Context(), r); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(out.String(), fixture.text) || !strings.Contains(out.String(), "[REDACTED]") {
					t.Fatalf("unsafe representation: %s", out.String())
				}
			})
		}
	}
}

func TestSlogWithGroupDepth(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		groups, explicit int
		rejected         bool
	}{{64, 0, false}, {65, 0, true}, {63, 1, false}, {64, 1, true}} {
		t.Run(fmt.Sprintf("%d/%d", fixture.groups, fixture.explicit), func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			h := embargo.NewSlogHandler(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: omitRecordTime}), embargo.NewScanner())
			for range fixture.groups {
				h = h.WithGroup("g")
			}
			attr := slog.String("value", "ok")
			for range fixture.explicit {
				attr = slog.Group("g", attr)
			}
			r := slog.NewRecord(time.Time{}, slog.LevelInfo, "event", 0)
			r.AddAttrs(attr)
			err := h.Handle(t.Context(), r)
			if (err != nil) != fixture.rejected || (fixture.rejected && !strings.Contains(out.String(), "record withheld (size limit)")) {
				t.Fatalf("err=%v output=%s", err, out.String())
			}
			bound := h.WithAttrs([]slog.Attr{attr})
			out.Reset()
			err = bound.Handle(t.Context(), slog.NewRecord(time.Time{}, slog.LevelInfo, "event", 0))
			if (err != nil) != fixture.rejected || (fixture.rejected && !strings.Contains(out.String(), "record withheld (size limit)")) {
				t.Fatalf("bound err=%v output=%s", err, out.String())
			}
		})
	}
}

func TestSlogMasksWithOriginalKeyAfterKeyRedaction(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	scanner := embargo.NewScanner(embargo.WithDetector(canaryDetector("cvv")))
	slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: omitRecordTime}), scanner)).Info("event", "cvv", 731)
	if strings.Contains(out.String(), "731") || strings.Count(out.String(), "[REDACTED]") != 2 {
		t.Fatal(out.String())
	}
}

func TestSlogScalarScanBudget(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	h := embargo.NewSlogHandler(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: omitRecordTime}), embargo.NewScanner())
	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "event", 0)
	r.AddAttrs(slog.String("large", strings.Repeat("x", 4<<20)))
	if err := h.Handle(t.Context(), r); err == nil || !strings.Contains(out.String(), "record withheld") {
		t.Fatal("oversized scalar was forwarded")
	}
}

func omitRecordTime(_ []string, attr slog.Attr) slog.Attr {
	if attr.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return attr
}

type cancelingScan struct {
	cancel context.CancelFunc
	calls  int
}

func (d *cancelingScan) Scan([]byte) []embargo.Finding { d.calls++; d.cancel(); return nil }

func TestSlogContextCancellation(t *testing.T) {
	t.Parallel()
	for _, alreadyCanceled := range []bool{true, false} {
		t.Run(strconv.FormatBool(alreadyCanceled), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if alreadyCanceled {
				cancel()
			}
			detector := &cancelingScan{cancel: cancel}
			scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector))
			var out bytes.Buffer
			h := embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), scanner)
			r := slog.NewRecord(time.Time{}, slog.LevelInfo, "event", 0)
			r.AddAttrs(slog.Any("data", map[string]any{"first": "public", "second": "public"}))
			err := h.Handle(ctx, r)
			want := 1
			if alreadyCanceled {
				want = 0
			}
			if err == nil || !strings.Contains(out.String(), "record withheld") || detector.calls != want {
				t.Fatalf("err=%v bytes=%d scans=%d want=%d", err, out.Len(), detector.calls, want)
			}
		})
	}
}

func TestSlogWithheldRecord(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{maskingReason, sizeReason, canceledReason} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			scanner := embargo.NewScanner()
			var value any = "planted-value"
			switch reason {
			case maskingReason:
				value = panicLogValue{}
			case sizeReason:
				value = strings.Repeat("x", 1<<20)
			case canceledReason:
				cancel()
			}
			var out bytes.Buffer
			handler := embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), scanner).WithAttrs([]slog.Attr{slog.String("planted-bound-key", "planted-bound-value")}).WithGroup("planted-group")
			record := slog.NewRecord(time.Unix(7, 0).UTC(), slog.LevelWarn, "planted-message", 123)
			record.AddAttrs(slog.Any("planted-key", struct{ Value any }{value}))
			if reason == maskingReason {
				record = slog.NewRecord(time.Unix(7, 0).UTC(), slog.LevelWarn, "planted-message", 123)
				record.AddAttrs(slog.Any("planted-key", value))
			}
			if !handler.Enabled(ctx, slog.LevelWarn) {
				t.Error("canceled record disabled before fallback")
			}
			if err := handler.Handle(ctx, record); err == nil {
				t.Fatal("missing handler error")
			}
			assertWithheldJSON(t, out.Bytes(), reason, 2)
			var got map[string]any
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["time"] != "1970-01-01T00:00:07Z" || got["level"] != "WARN" {
				t.Fatal("time or level changed", got)
			}
		})
	}
}

func assertWithheldJSON(t *testing.T, data []byte, reason string, count int) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("missing fallback: %v, bytes=%d", err, len(data))
	}
	if got["msg"] != "embargo: record withheld ("+reason+")" || got["withheld_attributes"] != float64(count) {
		t.Fatalf("wrong fallback: %s", data)
	}
	if bytes.Contains(data, []byte("planted")) || bytes.Contains(data, []byte("synthetic panic")) {
		t.Fatalf("fallback leaked: %s", data)
	}
}

//nolint:paralleltest // Isolate allocation accounting for the oversized scalar boundary.
func TestSlogRejectsLargePlainValuesBeforeEncoding(t *testing.T) {
	for _, value := range []any{strings.Repeat("x", 8<<20), bytes.Repeat([]byte("x"), 8<<20)} {
		handler := embargo.NewSlogHandler(slog.DiscardHandler, embargo.NewScanner())
		record := slog.NewRecord(time.Time{}, slog.LevelInfo, "event", 0)
		record.AddAttrs(slog.Any("large", value))
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		err := handler.Handle(t.Context(), record)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Fatal("oversized input accepted")
		}
		if after.TotalAlloc-before.TotalAlloc > 2<<20 {
			t.Fatalf("encoded oversized plain value: %d bytes allocated", after.TotalAlloc-before.TotalAlloc)
		}
	}
}

func BenchmarkSlogOversizedPlainValue(b *testing.B) {
	for _, size := range []int{1 << 20, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			handler := embargo.NewSlogHandler(slog.DiscardHandler, embargo.NewScanner())
			record := slog.NewRecord(time.Time{}, slog.LevelInfo, "event", 0)
			record.AddAttrs(slog.Any("large", bytes.Repeat([]byte("x"), size)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := handler.Handle(b.Context(), record); err == nil {
					b.Fatal("oversized value accepted")
				}
			}
		})
	}
}

func TestSlogDiagnosticSinkErrorRemainsObservable(t *testing.T) {
	t.Parallel()
	next := &inspectingHandler{enabled: true, err: io.ErrClosedPipe}
	handler := embargo.NewSlogHandler(next, embargo.NewScanner())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	record := slog.NewRecord(time.Unix(7, 0).UTC(), slog.LevelWarn, "planted-message", 123)
	record.AddAttrs(slog.String("planted-key", "planted-value"))
	err := handler.Handle(ctx, record)
	if !errors.Is(err, io.ErrClosedPipe) || !strings.Contains(err.Error(), "embargo: slog record could not be sanitized") {
		t.Fatal("diagnostic delivery lost one of its errors")
	}
	if next.handled != 1 || next.record.Message != "embargo: record withheld (canceled)" || next.record.NumAttrs() != 1 || next.record.PC != 0 {
		t.Fatal("diagnostic attempt retained original fields")
	}
}

func TestOutputTextHandlerGroupJoin(t *testing.T) {
	t.Parallel()
	s := embargo.NewScanner()
	var out bytes.Buffer
	l := slog.New(embargo.NewSlogHandler(slog.NewTextHandler(&out, &slog.HandlerOptions{ReplaceAttr: noTime}), s))
	l.WithGroup("alice@example").Info("m", "com", "x")
	l.Info("m", slog.Group("10.20", slog.String("30.40", "x")))
	got := out.String()
	t.Logf("%s", got)
	for _, leaked := range []string{"alice@example.com", "10.20.30.40"} {
		if f := s.ScanString(leaked); len(f) == 0 {
			t.Fatalf("control: %q is not detected", leaked)
		}
		if strings.Contains(got, leaked) {
			t.Errorf("TextHandler output contains %q", leaked)
		}
	}
}

func TestOutputSlogBytesBase64(t *testing.T) {
	t.Parallel()
	s := embargo.NewScanner()
	body := []byte(`{"email":"alice@example.com","card":"4111111111111111"}`)
	for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler {
			return slog.NewJSONHandler(b, &slog.HandlerOptions{ReplaceAttr: noTime})
		},
		"text": func(b *bytes.Buffer) slog.Handler {
			return slog.NewTextHandler(b, &slog.HandlerOptions{ReplaceAttr: noTime})
		},
	} {
		var out bytes.Buffer
		slog.New(embargo.NewSlogHandler(h(&out), s)).Info("request", "body", body)
		got := strings.TrimSpace(out.String())
		t.Logf("%s: %s", name, got)
		if strings.Contains(got, "eyJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwiY2FyZCI6IjQxMTExMTExMTExMTExMTEifQ==") {
			t.Errorf("%s: unmasked body bytes reached the output as base64", name)
		}
	}
}

func TestSlogByteContentsKeepPublicShape(t *testing.T) {
	t.Parallel()
	type namedBytes []byte
	for _, value := range []any{[]byte("public"), namedBytes("public"), []byte(nil)} {
		var out bytes.Buffer
		slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), embargo.NewScanner())).Info("entry", "data", value)
		var record map[string]json.RawMessage
		if err := json.Unmarshal(out.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(value)
		if err != nil || !bytes.Equal(record["data"], want) {
			t.Fatalf("public bytes changed: %s want=%s error=%v", out.Bytes(), want, err)
		}
	}
}
