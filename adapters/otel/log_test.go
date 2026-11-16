package embargootel_test

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	apilog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/trace"

	"github.com/nao1215/embargo"
	embargootel "github.com/nao1215/embargo/adapters/otel"
)

const (
	publicText   = "public"
	exampleEmail = "alice@example.com"
)

func reviewRecord(t *testing.T, limit int, attrs ...attribute.KeyValue) sdklog.Record {
	t.Helper()
	capture := &captureLog{}
	provider := sdklog.NewLoggerProvider(sdklog.WithAttributeCountLimit(limit), sdklog.WithProcessor(sdklog.NewSimpleProcessor(capture)))
	var record apilog.Record
	record.SetBody(attribute.StringValue(publicText))
	record.AddAttributes(attrs...)
	provider.Logger("review").Emit(t.Context(), record)
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(capture.records) != 1 {
		t.Fatal("missing fixture")
	}
	return capture.records[0]
}

func TestLogPreservesDroppedAttributesAndMetadata(t *testing.T) {
	t.Parallel()
	for _, field := range []attribute.KeyValue{attribute.String("status", "ok"), attribute.String("client_secret", "opaque-client-value")} {
		t.Run(string(field.Key), func(t *testing.T) {
			t.Parallel()
			before := reviewRecord(t, 1, field, attribute.String("second", publicText))
			if before.DroppedAttributes() != 1 {
				t.Fatal("fixture did not drop an attribute")
			}
			before.SetTimestamp(time.Unix(1, 0))
			before.SetObservedTimestamp(time.Unix(2, 0))
			before.SetSeverity(apilog.SeverityWarn)
			before.SetTraceID(trace.TraceID{1})
			before.SetSpanID(trace.SpanID{2})
			before.SetTraceFlags(trace.FlagsSampled)
			sink := &captureLog{}
			if err := embargootel.NewLogExporter(sink, embargo.NewScanner()).Export(t.Context(), []sdklog.Record{before}); err != nil {
				t.Fatal(err)
			}
			if len(sink.records) != 1 {
				t.Fatal("missing record")
			}
			after := sink.records[0]
			checkRecordMetadata(t, &before, &after)
			after.WalkAttributes(func(kv attribute.KeyValue) bool {
				want := field.Value.AsString()
				if string(field.Key) == "client_secret" {
					want = redacted
				}
				if kv.Key != field.Key || kv.Value.AsString() != want {
					t.Errorf("unexpected safe attribute: %v", kv)
				}
				return true
			})
			before.WalkAttributes(func(kv attribute.KeyValue) bool {
				if kv != field {
					t.Error("input changed")
				}
				return true
			})
		})
	}
}

type cancelDetector struct {
	cancel context.CancelFunc
	calls  int
}

func (d *cancelDetector) Scan([]byte) []embargo.Finding { d.calls++; d.cancel(); return nil }

func testExportCancellation(t *testing.T, export func(*testing.T, context.Context, *embargo.Scanner) error) {
	t.Helper()
	for _, preCanceled := range []bool{false, true} {
		name := "during scan"
		if preCanceled {
			name = "before scan"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if preCanceled {
				cancel()
			}
			detector := &cancelDetector{cancel: cancel}
			scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector))
			err := export(t, ctx, scanner)
			want := 1
			if preCanceled {
				want = 0
			}
			if err == nil || detector.calls != want {
				t.Fatalf("err=%v scans=%d want=%d", err, detector.calls, want)
			}
		})
	}
}

func TestLogExportCancellation(t *testing.T) {
	t.Parallel()
	record := reviewRecord(t, -1, attribute.String("field", publicText))
	testExportCancellation(t, func(t *testing.T, ctx context.Context, scanner *embargo.Scanner) error {
		t.Helper()
		sink := &captureLog{}
		err := embargootel.NewLogExporter(sink, scanner).Export(ctx, []sdklog.Record{record, record})
		if len(sink.records) != 0 {
			t.Error("canceled batch reached sink")
		}
		return err
	})
}

func checkRecordMetadata(t *testing.T, before, after *sdklog.Record) {
	t.Helper()
	if after.DroppedAttributes() != before.DroppedAttributes() || after.AttributesLen() != before.AttributesLen() {
		t.Fatalf("dropped before=%d after=%d", before.DroppedAttributes(), after.DroppedAttributes())
	}
	if after.Timestamp() != before.Timestamp() || after.ObservedTimestamp() != before.ObservedTimestamp() || after.Severity() != before.Severity() || after.TraceID() != before.TraceID() || after.SpanID() != before.SpanID() || after.TraceFlags() != before.TraceFlags() {
		t.Fatal("metadata changed")
	}
}

func TestLogRejectsCounterLosingKeyRename(t *testing.T) {
	t.Parallel()
	before := reviewRecord(t, 1, attribute.String(exampleEmail, "retained"), attribute.String("second", publicText))
	sink := &captureLog{}
	if err := embargootel.NewLogExporter(sink, embargo.NewScanner()).Export(t.Context(), []sdklog.Record{before}); err == nil {
		t.Fatal("unrepresentable rename accepted")
	}
	if len(sink.records) != 0 || before.DroppedAttributes() != 1 {
		t.Fatal("batch forwarded or source changed")
	}
	before.WalkAttributes(func(kv attribute.KeyValue) bool {
		if string(kv.Key) != exampleEmail {
			t.Error("source key changed")
		}
		return true
	})
}

func TestLogDuplicateModePreservesCountersOrRejects(t *testing.T) {
	t.Parallel()
	capture := &captureLog{}
	provider := sdklog.NewLoggerProvider(sdklog.WithAttributeCountLimit(1), sdklog.WithAllowKeyDuplication(), sdklog.WithProcessor(sdklog.NewSimpleProcessor(capture)))
	var input apilog.Record
	input.AddAttributes(attribute.String("password", "opaque"), attribute.String("second", publicText))
	provider.Logger("review").Emit(t.Context(), input)
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := capture.records[0]
	if before.DroppedAttributes() != 1 {
		t.Fatal("fixture did not drop an attribute")
	}
	sink := &captureLog{}
	if err := embargootel.NewLogExporter(sink, embargo.NewScanner()).Export(t.Context(), []sdklog.Record{before}); err == nil {
		t.Fatal("duplicate mode silently changed counters")
	}
	if len(sink.records) != 0 || before.DroppedAttributes() != 1 {
		t.Fatal("source changed or batch forwarded")
	}
	before.WalkAttributes(func(kv attribute.KeyValue) bool {
		if kv.Value.AsString() != "opaque" {
			t.Error("source value changed")
		}
		return true
	})
}
