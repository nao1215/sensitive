package embargootel

import (
	"context"
	"errors"
	"reflect"

	apilog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
	"github.com/nao1215/embargo/internal/saferecord"
)

// NewLogExporter checks cloned records before calling next.Export.
// Both dependencies must be non-nil. A failed record becomes a diagnostic with
// the same timestamp/severity and trace/span IDs/flags, a fixed body and
// withheld_attributes independent of SDK environment limits; original
// resource, scope and attributes are omitted. Other records remain independently
// masked. Cancellation uses the same fallback and a detached 100 ms export budget.
// Successful diagnostic delivery returns nil; downstream failures return a fixed error.
func NewLogExporter(next sdklog.Exporter, scanner *embargo.Scanner) sdklog.Exporter {
	output.Require(next)
	output.Require(scanner)
	return &logExporter{Exporter: next, scanner: scanner}
}

type logExporter struct {
	sdklog.Exporter

	scanner *embargo.Scanner
}

// Export checks the entire cloned batch before handing records to the wrapped exporter.
func (e *logExporter) Export(ctx context.Context, records []sdklog.Record) (err error) {
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Downstream panic values are not diagnostics.
		if !complete {
			err = errors.New("embargo: telemetry export failed")
		}
	}()

	safe := make([]sdklog.Record, len(records))
	for i := range records {
		safe[i] = e.safeLog(ctx, &records[i])
	}
	exportContext := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		exportContext, cancel = saferecord.Budget(ctx)
		defer cancel()
	}
	if err := e.Exporter.Export(exportContext, safe); err != nil {
		return errors.New("embargo: telemetry export failed")
	}
	complete = true
	return nil
}

func (e *logExporter) safeLog(ctx context.Context, original *sdklog.Record) (safe sdklog.Record) {
	var cause error
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Per-record recovery retains other records in the batch.
		if !complete {
			safe = withheldLog(ctx, original, cause)
		}
	}()
	if ctx.Err() != nil {
		return safe
	}
	safe = original.Clone()
	cause = maskLog(ctx, e.scanner, &safe)
	complete = cause == nil && ctx.Err() == nil
	return safe
}

// The SDK has no setters for resource or scope. Create fallback records through
// an isolated SDK provider instead of cloning immutable, potentially unsafe data.
func withheldLog(ctx context.Context, original *sdklog.Record, cause error) sdklog.Record {
	capture := &fallbackProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithResource(resource.Empty()), sdklog.WithAttributeCountLimit(1), sdklog.WithProcessor(capture))
	var record apilog.Record
	record.SetTimestamp(original.Timestamp())
	record.SetObservedTimestamp(original.ObservedTimestamp())
	record.SetSeverity(original.Severity())
	record.SetBody(attribute.StringValue(saferecord.Message(saferecord.Reason(ctx, cause))))
	count := original.AttributesLen() + len(original.Resource().Attributes()) + scopeAttributeCount(original.InstrumentationScope())
	record.AddAttributes(attribute.Int("withheld_attributes", count))
	detached, cancel := saferecord.Budget(ctx)
	defer cancel()
	provider.Logger("embargo").Emit(detached, record)
	_ = provider.Shutdown(detached) //nolint:errcheck // This private processor's Shutdown always succeeds.
	capture.record.SetTraceID(original.TraceID())
	capture.record.SetSpanID(original.SpanID())
	capture.record.SetTraceFlags(original.TraceFlags())
	return capture.record
}

type fallbackProcessor struct{ record sdklog.Record }

// OnEmit retains the SDK-created diagnostic record without exporting recursively.
func (p *fallbackProcessor) OnEmit(_ context.Context, record *sdklog.Record) error {
	p.record = record.Clone()
	return nil
}

// Shutdown owns no resources.
func (*fallbackProcessor) Shutdown(context.Context) error { return nil }

// ForceFlush has no buffered exports.
func (*fallbackProcessor) ForceFlush(context.Context) error { return nil }

func maskLog(ctx context.Context, scanner *embargo.Scanner, record *sdklog.Record) error {
	scope := record.InstrumentationScope()
	immutable := append(record.Resource().Attributes(), scope.Attributes.ToSlice()...)
	immutable = append(immutable, attribute.String("scope_name", scope.Name), attribute.String("scope_version", scope.Version), attribute.String("scope_schema", scope.SchemaURL), attribute.String("resource_schema", record.Resource().SchemaURL()))
	safe, err := maskAttributes(ctx, scanner, immutable)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(immutable, safe) {
		return errors.New("embargo: immutable telemetry field needs masking")
	}
	attrs := make([]attribute.KeyValue, 0, record.AttributesLen()+1)
	record.WalkAttributes(func(kv attribute.KeyValue) bool { attrs = append(attrs, kv); return true })
	attrs = append(attrs, attribute.KeyValue{Key: "body", Value: record.Body()})
	safe, err = maskAttributes(ctx, scanner, attrs)
	if err != nil {
		return err
	}
	record.SetBody(safe[len(safe)-1].Value)
	if err := replaceLogAttributes(record, attrs[:len(attrs)-1], safe[:len(safe)-1]); err != nil {
		return err
	}
	eventName, severityText := record.EventName(), record.SeverityText()
	if err := maskTextFields(ctx, scanner, &eventName, &severityText); err != nil {
		return err
	}
	record.SetEventName(eventName)
	record.SetSeverityText(severityText)
	return nil
}

// SetAttributes resets the SDK's private dropped count. Existing-key updates can
// preserve it with AddAttributes. Reject edits the public SDK cannot represent
// without losing evidence, including renames with prior drops or duplicate mode.
func replaceLogAttributes(record *sdklog.Record, original, safe []attribute.KeyValue) error {
	if reflect.DeepEqual(original, safe) {
		return nil
	}
	dropped := record.DroppedAttributes()
	if dropped == 0 {
		record.SetAttributes(safe...)
	} else {
		for i := range original {
			if original[i].Key != safe[i].Key {
				return errors.New("embargo: telemetry counters cannot be preserved")
			}
		}
		record.AddAttributes(safe...)
	}
	actual := make([]attribute.KeyValue, 0, record.AttributesLen())
	record.WalkAttributes(func(kv attribute.KeyValue) bool { actual = append(actual, kv); return true })
	if record.DroppedAttributes() != dropped || !reflect.DeepEqual(actual, safe) {
		return errors.New("embargo: telemetry counters cannot be preserved")
	}
	return nil
}

// Enabled admits the single diagnostic produced by this private provider.
func (*fallbackProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }

func scopeAttributeCount(scope instrumentation.Scope) int { return scope.Attributes.Len() }
