package tests

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

// sdkLogCapture observes the complete exported application payload, scope and
// resource in memory; no SDK network transport or global provider is installed.
type sdkLogCapture struct{ writer io.Writer }

func (c *sdkLogCapture) Export(_ context.Context, records []sdklog.Record) error {
	for i := range records {
		record := &records[i]
		attributes := map[string]any{}
		record.WalkAttributes(func(kv attribute.KeyValue) bool { attributes[string(kv.Key)] = kv.Value.String(); return true })
		payload := map[string]any{"body": record.Body().String(), "attributes": attributes, "resource": record.Resource().Attributes(), "scope": record.InstrumentationScope(), "severity": record.SeverityText(), "trace_id": record.TraceID().String(), "span_id": record.SpanID().String()}
		if err := json.NewEncoder(c.writer).Encode(payload); err != nil {
			return err
		}
	}
	return nil
}
func (*sdkLogCapture) Shutdown(context.Context) error   { return nil }
func (*sdkLogCapture) ForceFlush(context.Context) error { return nil }

func TestOTelLogOutputGuard(t *testing.T) {
	t.Parallel()
	for _, safe := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw-credential", true: "masked"}[safe], func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe, embargotest.WithScanner(embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))))
			provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(&sdkLogCapture{writer: r.Writer("otel/log")})))
			defer func() {
				if err := provider.Shutdown(context.Background()); err != nil {
					t.Error("shutdown failed")
				}
			}()
			text := errors.Join(errors.New("database: postgres://reader:forgotten@db.example/orders"), errors.New("token=opaque-service-value")).Error()
			if safe {
				scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
				text = embargo.Mask(text, scanner.ScanString(text))
			}
			var record otellog.Record
			record.SetBody(attribute.StringValue(text))
			record.AddAttributes(attribute.String("operation", "checkout"))
			provider.Logger("embargo-test").Emit(t.Context(), record)
			if err := provider.ForceFlush(t.Context()); err != nil {
				t.Fatal(err)
			}
			r.Expect("otel/log", func(data []byte) bool { return len(data) > 0 })
			if r.Check() != safe {
				t.Fatal("wrong OTel log verdict")
			}
			probe.finish()
		})
	}
}
