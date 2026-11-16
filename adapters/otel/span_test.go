package embargootel_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/otel/codes"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/nao1215/embargo"
	embargootel "github.com/nao1215/embargo/adapters/otel"
)

func TestSpanExportCancellation(t *testing.T) {
	t.Parallel()
	testExportCancellation(t, func(t *testing.T, ctx context.Context, scanner *embargo.Scanner) error {
		t.Helper()
		sink := &captureSpan{}
		span := tracetest.SpanStub{Name: publicText, Attributes: []attribute.KeyValue{attribute.String("field", publicText)}}.Snapshot()
		err := embargootel.NewSpanExporter(sink, scanner).ExportSpans(ctx, []sdktrace.ReadOnlySpan{span, span})
		if len(sink.spans) != 2 || sink.spans[0].Name() != withheldCanceled || sink.spans[1].Name() != withheldCanceled {
			t.Error("canceled batch did not emit fallback records")
		}
		return err
	})
}

func TestSpanPreservesTelemetryCounters(t *testing.T) {
	t.Parallel()
	when := time.Unix(1, 0)
	before := tracetest.SpanStub{
		Name: publicText, StartTime: when, EndTime: when.Add(time.Second),
		DroppedAttributes: 2, DroppedEvents: 3, DroppedLinks: 4, ChildSpanCount: 5,
		Events: []sdktrace.Event{{Name: exampleEmail, Time: when, Attributes: []attribute.KeyValue{attribute.String("password", "opaque")}, DroppedAttributeCount: 6}},
		Links:  []sdktrace.Link{{Attributes: []attribute.KeyValue{attribute.String("password", "opaque")}, DroppedAttributeCount: 7}},
	}.Snapshot()
	sink := &captureSpan{}
	if err := embargootel.NewSpanExporter(sink, embargo.NewScanner()).ExportSpans(t.Context(), []sdktrace.ReadOnlySpan{before}); err != nil {
		t.Fatal(err)
	}
	after := sink.spans[0]
	if after.DroppedAttributes() != 2 || after.DroppedEvents() != 3 || after.DroppedLinks() != 4 || after.ChildSpanCount() != 5 {
		t.Fatal("span counters changed")
	}
	if after.StartTime() != before.StartTime() || after.EndTime() != before.EndTime() || after.Events()[0].Time != when {
		t.Fatal("timestamps changed")
	}
	if after.Events()[0].DroppedAttributeCount != 6 || after.Links()[0].DroppedAttributeCount != 7 {
		t.Fatal("event or link counters changed")
	}
	if after.Events()[0].Name != redacted || after.Events()[0].Attributes[0].Value.AsString() != redacted || after.Links()[0].Attributes[0].Value.AsString() != redacted {
		t.Fatal("attributes leaked")
	}
	if before.Events()[0].Name != exampleEmail || before.Links()[0].Attributes[0].Value.AsString() != "opaque" {
		t.Fatal("source mutated")
	}
}

func TestSpanWithheldRecord(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{maskingReason, sizeReason, canceledReason} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			scanner := embargo.NewScanner()
			value := "planted-value"
			if reason == maskingReason {
				scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(auditPanicDetector{}))
			}
			if reason == sizeReason {
				value += strings.Repeat("x", 1<<20)
			}
			if reason == canceledReason {
				cancel()
			}
			before := tracetest.SpanStub{Name: "planted-name", StartTime: time.Unix(7, 0), EndTime: time.Unix(8, 0), Status: sdktrace.Status{Code: codes.Error, Description: "planted-status"}, Attributes: []attribute.KeyValue{attribute.String("planted-key", value)}}.Snapshot()
			sink := &captureSpan{}
			if err := embargootel.NewSpanExporter(sink, scanner).ExportSpans(ctx, []sdktrace.ReadOnlySpan{before}); err != nil {
				t.Fatal(err)
			}
			if len(sink.spans) != 1 {
				t.Fatal("missing fallback")
			}
			after := sink.spans[0]
			if after.Name() != "embargo: record withheld ("+reason+")" || after.StartTime() != before.StartTime() || after.EndTime() != before.EndTime() || after.Status().Code != before.Status().Code || after.Status().Description != "" {
				t.Fatal("wrong fallback metadata")
			}
			attrs := after.Attributes()
			if len(attrs) != 1 || string(attrs[0].Key) != "withheld_attributes" || attrs[0].Value.AsInt64() != 1 || len(after.Events()) != 0 || len(after.Links()) != 0 || len(after.Resource().Attributes()) != 0 {
				t.Fatal("original data retained")
			}
		})
	}
}

func TestSpanFallbackKeepsIdentityWithoutOriginalSpan(t *testing.T) {
	t.Parallel()
	before := tracetest.SpanStub{Name: "planted-name", SpanContext: trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled}), Resource: resource.Empty(), Attributes: []attribute.KeyValue{attribute.String("planted-key", "planted-value")}}.Snapshot()
	sink := &captureSpan{}
	if err := embargootel.NewSpanExporter(sink, embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(auditPanicDetector{}))).ExportSpans(t.Context(), []sdktrace.ReadOnlySpan{before}); err != nil {
		t.Fatal(err)
	}
	if len(sink.spans) != 1 || !sink.spans[0].SpanContext().Equal(before.SpanContext()) {
		t.Fatal("diagnostic lacks span identity")
	}
	embedded := reflect.ValueOf(sink.spans[0]).Elem().FieldByName("ReadOnlySpan")
	if embedded.IsValid() && !embedded.IsNil() {
		t.Fatal("diagnostic retains original span object")
	}
}
