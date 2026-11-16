package embargootel_test

import (
	"context"
	"math"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	apilog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/nao1215/embargo"
	embargootel "github.com/nao1215/embargo/adapters/otel"
)

const redacted = "[REDACTED]"

type captureLog struct{ records []sdklog.Record }

func (e *captureLog) Export(_ context.Context, records []sdklog.Record) error {
	for i := range records {
		e.records = append(e.records, records[i].Clone())
	}
	return nil
}
func (*captureLog) ForceFlush(context.Context) error { return nil }
func (*captureLog) Shutdown(context.Context) error   { return nil }

type captureSpan struct{ spans []sdktrace.ReadOnlySpan }

func (e *captureSpan) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.spans = append(e.spans, spans...)
	return nil
}
func (*captureSpan) Shutdown(context.Context) error { return nil }

func TestExportersThroughRealProviders(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner()
	logs := &captureLog{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(embargootel.NewLogExporter(logs, scanner))))
	var record apilog.Record
	record.SetBody(attribute.StringValue("alice@example.com failed"))
	record.AddAttributes(attribute.String("password", "synthetic-log-password"), attribute.Int64("count", 7), attribute.StringSlice("recipients", []string{"bob@example.com", "public"}))
	provider.Logger("checkout").Emit(t.Context(), record)
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(logs.records) != 1 || strings.Contains(logs.records[0].Body().AsString(), "alice@example.com") {
		t.Fatal("log body was not masked")
	}
	attrs := map[string]attribute.Value{}
	logs.records[0].WalkAttributes(func(kv attribute.KeyValue) bool { attrs[string(kv.Key)] = kv.Value; return true })
	if attrs["password"].AsString() != redacted || attrs["count"].AsInt64() != 7 || attrs["recipients"].AsStringSlice()[0] != redacted {
		t.Fatal(attrs)
	}
	if record.Body().AsString() != "alice@example.com failed" {
		t.Fatal("input record mutated")
	}
	spans := &captureSpan{}
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSyncer(embargootel.NewSpanExporter(spans, scanner)))
	_, span := tracer.Tracer("checkout").Start(t.Context(), "payment", trace.WithAttributes(attribute.String("token", "synthetic-span-token"), attribute.Int64("count", 9)))
	span.AddEvent("alice@example.com", trace.WithAttributes(attribute.String("password", "synthetic-event-password")))
	span.End()
	if err := tracer.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(spans.spans) != 1 {
		t.Fatal("missing span")
	}
	for _, kv := range spans.spans[0].Attributes() {
		if kv.Key == "token" && kv.Value.AsString() != redacted {
			t.Fatal(kv)
		}
	}
	if spans.spans[0].Events()[0].Name != redacted || spans.spans[0].Events()[0].Attributes[0].Value.AsString() != redacted {
		t.Fatal("span event leaked")
	}
}

func TestByteBodyRetainsItsTypeAndMasksText(t *testing.T) {
	t.Parallel()
	sink := &captureLog{}
	exporter := embargootel.NewLogExporter(sink, embargo.NewScanner())
	var record sdklog.Record
	record.SetBody(attribute.ByteSliceValue([]byte("alice@example.com")))
	if err := exporter.Export(t.Context(), []sdklog.Record{record}); err != nil {
		t.Fatal(err)
	}
	if got := string(sink.records[0].Body().AsByteSlice()); got != redacted {
		t.Fatalf("byte body became %s with value %q", sink.records[0].Body().Type(), got)
	}
}

type telemetryPanicDetector struct{}

func (*telemetryPanicDetector) Scan([]byte) []embargo.Finding { panic("sensitive telemetry panic") }

func TestLogExportFailureDoesNotForwardPartialBatch(t *testing.T) {
	t.Parallel()
	for _, scanner := range []*embargo.Scanner{embargo.NewScanner(), embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(&telemetryPanicDetector{}))} {
		sink := &captureLog{}
		exporter := embargootel.NewLogExporter(sink, scanner)
		var clean, invalid sdklog.Record
		clean.SetBody(attribute.StringValue("public"))
		invalid.SetBody(attribute.Float64Value(math.NaN()))
		err := exporter.Export(t.Context(), []sdklog.Record{clean, invalid})
		if err == nil || err.Error() != "embargo: telemetry export failed" || len(sink.records) != 0 {
			t.Fatal("partial batch or private failure forwarded")
		}
	}
}

func TestSensitiveResourceSuppressesLogBatch(t *testing.T) {
	t.Parallel()
	sink := &captureLog{}
	provider := sdklog.NewLoggerProvider(sdklog.WithResource(resource.NewWithAttributes("", attribute.String("password", "resource-password"))), sdklog.WithProcessor(sdklog.NewSimpleProcessor(embargootel.NewLogExporter(sink, embargo.NewScanner()))))
	var record apilog.Record
	record.SetBody(attribute.StringValue("public"))
	provider.Logger("checkout").Emit(t.Context(), record)
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 0 {
		t.Fatal("immutable resource leaked")
	}
}

func TestSpanResourceScopeLinksAndStatusAreMasked(t *testing.T) {
	t.Parallel()
	sink := &captureSpan{}
	provider := sdktrace.NewTracerProvider(sdktrace.WithResource(resource.NewWithAttributes("", attribute.String("password", "span-resource-secret"))), sdktrace.WithSyncer(embargootel.NewSpanExporter(sink, embargo.NewScanner())))
	_, span := provider.Tracer("alice@example.com", trace.WithInstrumentationAttributes(attribute.String("token", "scope-secret"))).Start(t.Context(), "bob@example.com", trace.WithLinks(trace.Link{SpanContext: trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}}), Attributes: []attribute.KeyValue{attribute.String("password", "link-secret")}}))
	span.SetStatus(codes.Error, "password=status-secret")
	span.End()
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := sink.spans[0]
	if got.Name() != redacted || got.InstrumentationScope().Name != redacted || got.Status().Description != "password=[REDACTED]" {
		t.Fatal("span text leaked")
	}
	if got.Resource().Attributes()[0].Value.AsString() != redacted || got.Links()[0].Attributes[0].Value.AsString() != redacted {
		t.Fatal("span metadata leaked")
	}
}
