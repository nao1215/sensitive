package embargootel_test

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/nao1215/embargo"
	embargootel "github.com/nao1215/embargo/adapters/otel"
)

func ExampleNewLogExporter() {
	sink := &captureLog{}
	exporter := embargootel.NewLogExporter(sink, embargo.NewScanner())
	var record sdklog.Record
	record.SetBody(attribute.StringValue("password=opaque-password"))
	if err := exporter.Export(context.Background(), []sdklog.Record{record}); err != nil {
		panic(err)
	}
	fmt.Println(sink.records[0].Body().AsString())
	// Output: password=[REDACTED]
}

func ExampleNewSpanExporter() {
	sink := &captureSpan{}
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(embargootel.NewSpanExporter(sink, embargo.NewScanner())))
	_, span := provider.Tracer("checkout").Start(context.Background(), "pay", trace.WithAttributes(attribute.String("email", "alice@example.com")))
	span.End()
	if err := provider.Shutdown(context.Background()); err != nil {
		panic(err)
	}
	fmt.Println(sink.spans[0].Attributes()[0].Value.AsString())
	// Output: [REDACTED]
}

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
