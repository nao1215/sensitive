package embargootel

import (
	"context"
	"errors"
	"slices"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
)

// NewSpanExporter copies span text and attributes before export, including events and links.
// Resource and scope attributes are masked too; times, counts and trace identifiers stay intact.
// Span, parent and link contexts omit vendor TraceState values.
// Nil dependencies panic. Invalid values and failed exports return a fixed error without a partial batch.
func NewSpanExporter(next sdktrace.SpanExporter, scanner *embargo.Scanner) sdktrace.SpanExporter {
	output.Require(next)
	output.Require(scanner)
	return &spanExporter{SpanExporter: next, scanner: scanner}
}

type spanExporter struct {
	sdktrace.SpanExporter

	scanner *embargo.Scanner
}

// ExportSpans forwards complete sanitized views or returns a fixed failure.
func (e *spanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) (err error) {
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Reject a failed span batch without exposing the panic.
		if !complete {
			err = errors.New("embargo: span export failed")
		}
	}()
	safe := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, span := range spans {
		masked, err := maskSpan(e.scanner, span)
		if err != nil {
			return errors.New("embargo: span export failed")
		}
		safe[i] = masked
	}
	if err := e.SpanExporter.ExportSpans(ctx, safe); err != nil {
		return errors.New("embargo: span export failed")
	}
	complete = true
	return nil
}

type spanView struct {
	sdktrace.ReadOnlySpan

	resource *resource.Resource
	scope    instrumentation.Scope
	status   sdktrace.Status
	name     string
	attrs    []attribute.KeyValue
	events   []sdktrace.Event
	links    []sdktrace.Link
	context  trace.SpanContext
	parent   trace.SpanContext
}

// SpanContext keeps the span identity without forwarding vendor TraceState.
func (s *spanView) SpanContext() trace.SpanContext { return s.context }

// Parent retains the parent reference with its TraceState removed.
func (s *spanView) Parent() trace.SpanContext { return s.parent }

// Name supplies the sanitized operation name.
func (s *spanView) Name() string { return s.name }

// Attributes exposes the copied span fields.
func (s *spanView) Attributes() []attribute.KeyValue { return s.attrs }

// Events contains masked names and attributes with original timestamps.
func (s *spanView) Events() []sdktrace.Event { return s.events }

// Links retains trace references and replaces their attribute slices.
func (s *spanView) Links() []sdktrace.Link { return s.links }

// Status preserves the code and masks its description.
func (s *spanView) Status() sdktrace.Status { return s.status }

// InstrumentationScope carries the copied instrumentation metadata.
func (s *spanView) InstrumentationScope() instrumentation.Scope { return s.scope }

// InstrumentationLibrary serves the same safe scope to legacy exporters.
func (s *spanView) InstrumentationLibrary() instrumentation.Scope { return s.scope }

// Resource returns a resource rebuilt from sanitized attributes.
func (s *spanView) Resource() *resource.Resource { return s.resource }

func maskSpan(scanner *embargo.Scanner, original sdktrace.ReadOnlySpan) (sdktrace.ReadOnlySpan, error) {
	view := &spanView{ReadOnlySpan: original, context: original.SpanContext().WithTraceState(trace.TraceState{}), parent: original.Parent().WithTraceState(trace.TraceState{}), name: maskText(scanner, original.Name()), events: slices.Clone(original.Events()), links: slices.Clone(original.Links()), status: original.Status(), scope: original.InstrumentationScope()}
	var err error
	if view.attrs, err = maskAttributes(scanner, original.Attributes()); err != nil {
		return nil, err
	}
	for i := range view.events {
		view.events[i].Name = maskText(scanner, view.events[i].Name)
		if view.events[i].Attributes, err = maskAttributes(scanner, view.events[i].Attributes); err != nil {
			return nil, err
		}
	}
	for i := range view.links {
		view.links[i].SpanContext = view.links[i].SpanContext.WithTraceState(trace.TraceState{})
		if view.links[i].Attributes, err = maskAttributes(scanner, view.links[i].Attributes); err != nil {
			return nil, err
		}
	}
	view.status.Description = maskText(scanner, view.status.Description)
	attrs, err := maskAttributes(scanner, original.Resource().Attributes())
	if err != nil {
		return nil, err
	}
	view.resource = resource.NewWithAttributes(maskText(scanner, original.Resource().SchemaURL()), attrs...)
	attrs, err = maskAttributes(scanner, view.scope.Attributes.ToSlice())
	if err != nil {
		return nil, err
	}
	view.scope.Attributes = attribute.NewSet(attrs...)
	view.scope.Name = maskText(scanner, view.scope.Name)
	view.scope.Version = maskText(scanner, view.scope.Version)
	view.scope.SchemaURL = maskText(scanner, view.scope.SchemaURL)
	return view, nil
}
