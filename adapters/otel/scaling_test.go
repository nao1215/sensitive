package embargootel_test

import (
	"context"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/nao1215/embargo"
	embargootel "github.com/nao1215/embargo/adapters/otel"
)

type discardLog struct{}

func (*discardLog) Export(context.Context, []sdklog.Record) error { return nil }
func (*discardLog) Shutdown(context.Context) error                { return nil }
func (*discardLog) ForceFlush(context.Context) error              { return nil }

type discardSpan struct{}

func (*discardSpan) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error { return nil }
func (*discardSpan) Shutdown(context.Context) error                             { return nil }

func otelScalingCall(tb testing.TB, size int) func() {
	tb.Helper()
	scanner := embargo.NewScanner(embargo.WithAll())
	logs := embargootel.NewLogExporter(&discardLog{}, scanner)
	spans := embargootel.NewSpanExporter(&discardSpan{}, scanner)
	var record sdklog.Record
	record.SetBody(attribute.StringValue(strings.Repeat("x", size)))
	span := tracetest.SpanStub{Name: "operation", Attributes: []attribute.KeyValue{attribute.String("public", strings.Repeat("x", size))}}.Snapshot()
	return func() {
		if err := logs.Export(tb.Context(), []sdklog.Record{record}); err != nil && size < 1<<20 {
			tb.Fatal(err)
		}
		if err := spans.ExportSpans(tb.Context(), []sdktrace.ReadOnlySpan{span}); err != nil && size < 1<<20 {
			tb.Fatal(err)
		}
	}
}

//nolint:paralleltest // ReadMemStats measures both wrappers as one isolated operation.
func TestHookAllocationBudget(t *testing.T) {
	const size = 64 << 10
	call := otelScalingCall(t, size)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 128*size+1<<20 {
		t.Fatal("OpenTelemetry hook allocation amplification")
	}
}

func BenchmarkHookScaling(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			call := otelScalingCall(b, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				call()
			}
		})
	}
}
