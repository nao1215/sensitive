package embargootel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	apilog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/nao1215/embargo"
	embargootel "github.com/nao1215/embargo/adapters/otel"
)

func TestMaskedKeyCollisionNeverRestoresOriginal(t *testing.T) {
	t.Parallel()
	const pan = 4111111111111111
	for _, value := range []attribute.Value{attribute.Float64Value(pan), attribute.Int64SliceValue([]int64{pan}), attribute.Float64SliceValue([]float64{pan})} {
		t.Run(value.Type().String(), func(t *testing.T) {
			t.Parallel()
			clean := attribute.Int64Value(7)
			if value.Type() != attribute.FLOAT64 {
				clean = attribute.Int64SliceValue([]int64{7})
			}
			collision := attribute.MapValue(attribute.KeyValue{Key: "a@example.com", Value: value}, attribute.KeyValue{Key: "z@example.com", Value: clean})
			record := reviewRecord(t, -1, attribute.KeyValue{Key: "data", Value: collision})
			record.SetBody(collision)
			logs := &captureLog{}
			if err := embargootel.NewLogExporter(logs, embargo.NewScanner()).Export(t.Context(), []sdklog.Record{record}); err != nil {
				t.Fatal(err)
			}
			if len(logs.records) != 1 || logs.records[0].AttributesLen() != 1 {
				t.Fatal("missing log")
			}
			checkCollisionValue(t, logs.records[0].Body(), clean)
			logs.records[0].WalkAttributes(func(kv attribute.KeyValue) bool { checkCollisionValue(t, kv.Value, clean); return true })
			spans := &captureSpan{}
			span := tracetest.SpanStub{Name: publicText, Attributes: []attribute.KeyValue{{Key: "data", Value: collision}}}.Snapshot()
			if err := embargootel.NewSpanExporter(spans, embargo.NewScanner()).ExportSpans(t.Context(), []sdktrace.ReadOnlySpan{span}); err != nil {
				t.Fatal(err)
			}
			if len(spans.spans) != 1 || len(spans.spans[0].Attributes()) != 1 {
				t.Fatal("missing span")
			}
			checkCollisionValue(t, spans.spans[0].Attributes()[0].Value, clean)
		})
	}
}

func checkCollisionValue(t *testing.T, value, clean attribute.Value) {
	t.Helper()
	fields := value.AsMap()
	if len(fields) != 1 || string(fields[0].Key) != redacted {
		t.Fatalf("unexpected map: %v", value)
	}
	got, err := json.Marshal(fields[0].Value.AsInterface())
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(clean.AsInterface())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "4111111111111111") || !bytes.Equal(got, want) {
		t.Errorf("masked winner %s restored as %s", want, got)
	}
}

const redacted = "[REDACTED]"

func TestExportersThroughRealProviders(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner()
	logs := &captureLog{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(embargootel.NewLogExporter(logs, scanner))))
	var record apilog.Record
	record.SetBody(attribute.StringValue("alice@example.com failed"))
	record.AddAttributes(attribute.String("password", "synthetic-log-password"), attribute.Int64("count", 7), attribute.StringSlice("recipients", []string{"bob@example.com", publicText}))
	provider.Logger("checkout").Emit(t.Context(), record)
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(logs.records) != 1 || strings.Contains(logs.records[0].Body().AsString(), exampleEmail) {
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
	span.AddEvent(exampleEmail, trace.WithAttributes(attribute.String("password", "synthetic-event-password")))
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
	record.SetBody(attribute.ByteSliceValue([]byte(exampleEmail)))
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
		clean.SetBody(attribute.StringValue(publicText))
		invalid.SetBody(attribute.Float64Value(math.NaN()))
		err := exporter.Export(t.Context(), []sdklog.Record{clean, invalid})
		if err != nil || len(sink.records) != 2 || sink.records[1].Body().AsString() != withheldMasking {
			t.Fatal("partial batch or private failure forwarded")
		}
	}
}

func TestSensitiveResourceSuppressesLogBatch(t *testing.T) {
	t.Parallel()
	sink := &captureLog{}
	provider := sdklog.NewLoggerProvider(sdklog.WithResource(resource.NewWithAttributes("", attribute.String("password", "resource-password"))), sdklog.WithProcessor(sdklog.NewSimpleProcessor(embargootel.NewLogExporter(sink, embargo.NewScanner()))))
	var record apilog.Record
	record.SetBody(attribute.StringValue(publicText))
	provider.Logger("checkout").Emit(t.Context(), record)
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || sink.records[0].Body().AsString() != withheldMasking || len(sink.records[0].Resource().Attributes()) != 0 {
		t.Fatal("immutable resource leaked")
	}
}

func TestSpanResourceScopeLinksAndStatusAreMasked(t *testing.T) {
	t.Parallel()
	sink := &captureSpan{}
	provider := sdktrace.NewTracerProvider(sdktrace.WithResource(resource.NewWithAttributes("", attribute.String("password", "span-resource-secret"))), sdktrace.WithSyncer(embargootel.NewSpanExporter(sink, embargo.NewScanner())))
	_, span := provider.Tracer(exampleEmail, trace.WithInstrumentationAttributes(attribute.String("token", "scope-secret"))).Start(t.Context(), "bob@example.com", trace.WithLinks(trace.Link{SpanContext: trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}}), Attributes: []attribute.KeyValue{attribute.String("password", "link-secret")}}))
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

func TestLogBodyValueShapes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input, want attribute.Value
		name        string
	}{
		{attribute.Value{}, attribute.Value{}, "null"},
		{attribute.BoolValue(true), attribute.BoolValue(true), "bool"},
		{attribute.Int64Value(7), attribute.Int64Value(7), "int"},
		{attribute.Float64Value(3.25), attribute.Float64Value(3.25), "float"},
		{attribute.Int64SliceValue([]int64{7, 8}), attribute.Int64SliceValue([]int64{7, 8}), "ints"},
		{attribute.BoolSliceValue([]bool{true, false}), attribute.BoolSliceValue([]bool{true, false}), "bools"},
		{attribute.Float64SliceValue([]float64{3.25, 4.5}), attribute.Float64SliceValue([]float64{3.25, 4.5}), "floats"},
		{attribute.ByteSliceValue([]byte{0xff, 'x'}), attribute.ByteSliceValue([]byte{0xff, 'x'}), "invalid-utf8-bytes"},
		{attribute.MapValue(attribute.KeyValue{Key: "items", Value: attribute.SliceValue(attribute.ByteSliceValue([]byte(exampleEmail)), attribute.BoolValue(true))}), attribute.MapValue(attribute.KeyValue{Key: "items", Value: attribute.SliceValue(attribute.ByteSliceValue([]byte(redacted)), attribute.BoolValue(true))}), "nested"},
		{attribute.MapValue(attribute.KeyValue{Key: exampleEmail, Value: attribute.ByteSliceValue([]byte(publicText))}), attribute.MapValue(attribute.KeyValue{Key: redacted, Value: attribute.ByteSliceValue([]byte(publicText))}), "masked-map-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink := &captureLog{}
			exporter := embargootel.NewLogExporter(sink, embargo.NewScanner(embargo.WithKinds(embargo.KindEmail)))
			var record sdklog.Record
			record.SetBody(tc.input)
			if err := exporter.Export(t.Context(), []sdklog.Record{record}); err != nil {
				t.Fatal(err)
			}
			got := sink.records[0].Body()
			if got.Type() != tc.want.Type() || !reflect.DeepEqual(got.AsInterface(), tc.want.AsInterface()) {
				t.Fatalf("body %v, want %v", got, tc.want)
			}
			if !reflect.DeepEqual(record.Body().AsInterface(), tc.input.AsInterface()) {
				t.Fatal("input body changed")
			}
		})
	}
}

func TestSpanInvalidValuesSuppressWholeBatch(t *testing.T) {
	t.Parallel()
	bad := attribute.Float64(publicText, math.NaN())
	for index, stub := range []tracetest.SpanStub{
		{Attributes: []attribute.KeyValue{bad}},
		{Events: []sdktrace.Event{{Attributes: []attribute.KeyValue{bad}}}},
		{Links: []sdktrace.Link{{Attributes: []attribute.KeyValue{bad}}}},
		{Resource: resource.NewSchemaless(bad)},
		{InstrumentationScope: instrumentation.Scope{Name: "checkout", Attributes: attribute.NewSet(bad)}},
	} {
		if stub.Resource == nil {
			stub.Resource = resource.Empty()
		}
		sink := &captureSpan{}
		exporter := embargootel.NewSpanExporter(sink, embargo.NewScanner())
		clean := tracetest.SpanStub{Name: publicText, Resource: resource.Empty()}.Snapshot()
		err := exporter.ExportSpans(t.Context(), []sdktrace.ReadOnlySpan{clean, stub.Snapshot()})
		if err != nil || len(sink.spans) != 2 || sink.spans[0].Name() != publicText || sink.spans[1].Name() != withheldMasking {
			t.Fatalf("span case %d: error=%v, forwarded=%d", index, err, len(sink.spans))
		}
	}
}

type failedExporter struct{ panicOnExport bool }

func (e *failedExporter) failure() error {
	if e.panicOnExport {
		panic("private exporter panic")
	}
	return errors.New("private exporter error")
}

func (e *failedExporter) Export(context.Context, []sdklog.Record) error { return e.failure() }

func (e *failedExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	return e.failure()
}

func (*failedExporter) Shutdown(context.Context) error { return nil }

func (*failedExporter) ForceFlush(context.Context) error { return nil }

func TestExporterFailuresReturnFixedErrors(t *testing.T) {
	t.Parallel()
	for _, panicOnExport := range []bool{false, true} {
		next := &failedExporter{panicOnExport: panicOnExport}
		logs := embargootel.NewLogExporter(next, embargo.NewScanner())
		spans := embargootel.NewSpanExporter(next, embargo.NewScanner())
		if err := logs.Export(t.Context(), nil); err == nil || err.Error() != "embargo: telemetry export failed" {
			t.Fatal("log exporter disclosed private failure")
		}
		if err := spans.ExportSpans(t.Context(), nil); err == nil || err.Error() != "embargo: span export failed" {
			t.Fatal("span exporter disclosed private failure")
		}
	}
}

func TestLogBodyNestingLimitSuppressesOutput(t *testing.T) {
	t.Parallel()
	value := attribute.StringValue(publicText)
	for range 65 {
		value = attribute.SliceValue(value)
	}
	sink := &captureLog{}
	exporter := embargootel.NewLogExporter(sink, embargo.NewScanner())
	var record sdklog.Record
	record.SetBody(value)
	if err := exporter.Export(t.Context(), []sdklog.Record{record}); err != nil || len(sink.records) != 1 || sink.records[0].Body().AsString() != "embargo: record withheld (size limit)" {
		t.Fatal("unbounded nesting was forwarded")
	}
}

func TestOversizedLogBodyIsNotExported(t *testing.T) {
	t.Parallel()
	sink := &captureLog{}
	exporter := embargootel.NewLogExporter(sink, embargo.NewScanner())
	var record sdklog.Record
	record.SetBody(attribute.StringValue(strings.Repeat("x", 1<<20)))
	if err := exporter.Export(t.Context(), []sdklog.Record{record}); err != nil || len(sink.records) != 1 || sink.records[0].Body().AsString() != "embargo: record withheld (size limit)" {
		t.Fatal("oversized log body was exported")
	}
}

func TestSpanContextsOmitTraceStateWithoutChangingIdentity(t *testing.T) {
	t.Parallel()
	state, err := trace.ParseTraceState("tenant=alice@example.com,session=opaque-session")
	if err != nil {
		t.Fatal(err)
	}
	original := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled, Remote: true, TraceState: state})
	span := tracetest.SpanStub{Name: "checkout", Resource: resource.Empty(), SpanContext: original, Parent: original, Links: []sdktrace.Link{{SpanContext: original}}}.Snapshot()
	next := &captureSpan{}
	if err := embargootel.NewSpanExporter(next, embargo.NewScanner()).ExportSpans(t.Context(), []sdktrace.ReadOnlySpan{span}); err != nil {
		t.Fatal(err)
	}
	got := next.spans[0]
	for _, context := range []trace.SpanContext{got.SpanContext(), got.Parent(), got.Links()[0].SpanContext} {
		if context.TraceState().Len() != 0 {
			t.Error("exported private TraceState")
		}
		if context.TraceID() != original.TraceID() || context.SpanID() != original.SpanID() || context.TraceFlags() != original.TraceFlags() || context.IsRemote() != original.IsRemote() {
			t.Error("span identity changed")
		}
	}
	if span.SpanContext().TraceState().String() != state.String() || span.Links()[0].SpanContext.TraceState().String() != state.String() {
		t.Fatal("source span mutated")
	}
}

func TestAttributeOriginalKeyContext(t *testing.T) {
	t.Parallel()
	sink := &captureLog{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(embargootel.NewLogExporter(sink, embargo.NewScanner()))))
	var record apilog.Record
	record.AddAttributes(attribute.Int64("cvv", 731), attribute.String("client_secret", "opaque-client-value"), attribute.String("expiry", "12/29"))
	provider.Logger("checkout").Emit(t.Context(), record)
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || sink.records[0].AttributesLen() != 3 {
		t.Fatal("missing attributes")
	}
	sink.records[0].WalkAttributes(func(kv attribute.KeyValue) bool {
		if kv.Value.AsString() != redacted {
			t.Errorf("unmasked: %v", kv)
		}
		return true
	})
}
