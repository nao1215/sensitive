package embargootel

import (
	"context"
	"errors"
	"reflect"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
)

// NewLogExporter checks cloned records before calling next.Export.
// Both dependencies must be non-nil. Sensitive resource or instrumentation fields
// cannot be replaced through the SDK record API, so those batches are rejected.
// All masking completes before any record is forwarded; failures return a fixed error.
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
		_ = recover() //nolint:errcheck // Export failures must not disclose panic values.
		if !complete {
			err = errors.New("embargo: telemetry export failed")
		}
	}()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	safe := make([]sdklog.Record, len(records))
	for i := range records {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		safe[i] = records[i].Clone()
		if err := maskLog(ctx, e.scanner, &safe[i]); err != nil {
			return errors.New("embargo: telemetry export failed")
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := e.Exporter.Export(ctx, safe); err != nil {
		return errors.New("embargo: telemetry export failed")
	}
	complete = true
	return nil
}

func maskLog(ctx context.Context, scanner *embargo.Scanner, record *sdklog.Record) error {
	scope := record.InstrumentationScope()
	immutable := append(record.Resource().Attributes(), scope.Attributes.ToSlice()...)
	immutable = append(immutable, attribute.String("scope_name", scope.Name), attribute.String("scope_version", scope.Version), attribute.String("scope_schema", scope.SchemaURL), attribute.String("resource_schema", record.Resource().SchemaURL()))
	safe, err := maskAttributes(ctx, scanner, immutable)
	if err != nil || !reflect.DeepEqual(immutable, safe) {
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
