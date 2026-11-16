package embargootel_test

import (
	"context"
	"testing"
	"time"

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
		if len(sink.spans) != 0 {
			t.Error("canceled batch reached sink")
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
