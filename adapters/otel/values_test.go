package embargootel_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

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
