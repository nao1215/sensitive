package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

//nolint:gocognit,goconst // Keep the expected outputs and failure modes together in this acceptance matrix.
func checkOTelAcceptance(t *testing.T) {
	t.Helper()
	for _, mode := range []string{"safe", "raw-error", "missing-flush", "regressed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe)
			d := signingFailed()
			exporter := tracetest.NewInMemoryExporter()
			recorder := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(time.Minute)), sdktrace.WithSpanProcessor(recorder))
			defer func() {
				if err := provider.Shutdown(context.Background()); err != nil {
					t.Error("SDK shutdown failed")
				}
			}()
			_, span := provider.Tracer("embargo-test").Start(context.Background(), "signer.sign")
			if mode == "raw-error" {
				span.RecordError(errors.New(string(r.Canary())), trace.WithStackTrace(true))
			} else {
				selected := d
				if mode == "regressed" {
					selected = withheld()
				}
				span.AddEvent("signer.failure", trace.WithAttributes(attribute.String("code", selected.code), attribute.String("message", selected.message), attribute.String("key", embargo.NewSecret(string(r.Canary())).String())))
				span.SetStatus(codes.Error, selected.message)
			}
			span.End()
			if len(recorder.Ended()) != 1 {
				t.Fatal("real span recorder did not receive event")
			}
			if mode != "missing-flush" {
				if err := provider.ForceFlush(context.Background()); err != nil {
					t.Fatal("SDK flush failed")
				}
			}
			// Marshal the entire SDK export, including resource, scope, status and events.
			if err := json.NewEncoder(r.Writer("sdk")).Encode(exporter.GetSpans()); err != nil {
				t.Fatal("export serialization failed")
			}
			r.Expect("sdk", func(data []byte) bool {
				//nolint:tagliatelle // The OTel SpanStub JSON uses SDK field names.
				var spans []struct {
					SpanContext struct {
						TraceID string `json:"TraceID"`
						SpanID  string `json:"SpanID"`
					} `json:"SpanContext"`
					Name   string `json:"Name"`
					Events []struct {
						Attributes []struct {
							Key   string `json:"Key"`
							Value struct {
								Type  string `json:"Type"`
								Value string `json:"Value"`
							} `json:"Value"`
						} `json:"Attributes"`
					} `json:"Events"`
					Status struct {
						Code codes.Code `json:"Code"`
					} `json:"Status"`
				}
				if json.Unmarshal(data, &spans) != nil || len(spans) != 1 || spans[0].SpanContext.TraceID != span.SpanContext().TraceID().String() || spans[0].SpanContext.SpanID != span.SpanContext().SpanID().String() || spans[0].Name != "signer.sign" || len(spans[0].Events) != 1 || spans[0].Status.Code != codes.Error {
					return false
				}
				attrs := make(map[string]string)
				for _, a := range spans[0].Events[0].Attributes {
					attrs[a.Key] = a.Value.Value
				}
				return attrs["code"] == d.code && attrs["message"] == d.message && attrs["key"] == "[REDACTED]"
			})
			if r.Check() != (mode == "safe") {
				t.Fatal("telemetry detector returned wrong verdict")
			}
			probe.finish()
		})
	}
}
