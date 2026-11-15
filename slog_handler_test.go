package embargo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
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
			if err == nil || err.Error() != "embargo: slog record could not be sanitized" || next.handled != 0 {
				t.Fatal("failed normalization reached downstream")
			}
		}
	}
	next := &inspectingHandler{}
	handler := embargo.NewSlogHandler(next, embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(panicDetector{})))
	err := handler.WithGroup("private").Handle(t.Context(), slog.NewRecord(time.Time{}, slog.LevelInfo, "message", 0))
	if err == nil || err.Error() != "embargo: slog record could not be sanitized" || next.handled != 0 {
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
		if err := handler.Handle(t.Context(), record); err == nil || next.handled != 0 {
			t.Fatal("nil panic reached downstream")
		}
	}
}
