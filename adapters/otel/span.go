package embargootel

import (
	"context"
	"errors"
	"slices"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
	"github.com/nao1215/embargo/internal/saferecord"
)

// NewSpanExporter copies span text and attributes before export, including events and links.
// Resource and scope attributes are masked too; times, counts and trace identifiers stay intact.
// Span, parent and link contexts omit vendor TraceState values.
// Nil dependencies panic. Masking failures, limits and cancellation replace each
// affected span with a fixed diagnostic name and withheld_attributes. Time and
// status code survive; original fields, events, links, resource and scope do not.
// Canceled export uses a detached 100 ms budget. Successful diagnostics return nil;
// downstream failures return a fixed error without original values.
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
		_ = recover() //nolint:errcheck // Downstream panic values are not diagnostics.
		if !complete {
			err = errors.New("embargo: span export failed")
		}
	}()

	safe := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, span := range spans {
		safe[i] = e.safeSpan(ctx, span)
	}
	exportContext := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		exportContext, cancel = saferecord.Budget(ctx)
		defer cancel()
	}
	if err := e.SpanExporter.ExportSpans(exportContext, safe); err != nil {
		return errors.New("embargo: span export failed")
	}
	complete = true
	return nil
}

func (e *spanExporter) safeSpan(ctx context.Context, original sdktrace.ReadOnlySpan) (safe sdktrace.ReadOnlySpan) {
	var cause error
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Keep panic payloads out of the export.
		if !complete {
			safe = withheldSpan(ctx, original, cause)
		}
	}()
	if ctx.Err() != nil {
		return nil
	}
	safe, cause = maskSpan(ctx, e.scanner, original)
	complete = cause == nil && ctx.Err() == nil
	return safe
}

func withheldSpan(ctx context.Context, original sdktrace.ReadOnlySpan, cause error) sdktrace.ReadOnlySpan {
	count := len(original.Attributes()) + len(original.Resource().Attributes()) + scopeAttributeCount(original.InstrumentationScope())
	for _, event := range original.Events() {
		count += len(event.Attributes)
	}
	for _, link := range original.Links() {
		count += len(link.Attributes)
	}
	view := newSpanView(original)
	view.name = saferecord.Message(saferecord.Reason(ctx, cause))
	view.attrs = []attribute.KeyValue{attribute.Int("withheld_attributes", count)}
	view.resource = resource.Empty()
	view.status = sdktrace.Status{Code: original.Status().Code}
	return view
}

type spanView struct {
	sdktrace.ReadOnlySpan

	resource          *resource.Resource
	start             time.Time
	end               time.Time
	scope             instrumentation.Scope
	status            sdktrace.Status
	name              string
	attrs             []attribute.KeyValue
	events            []sdktrace.Event
	links             []sdktrace.Link
	context           trace.SpanContext
	parent            trace.SpanContext
	kind              trace.SpanKind
	droppedAttributes int
	droppedEvents     int
	droppedLinks      int
	children          int
}

// newSpanView copies structural metadata and never retains the original span.
// The nil embedded interface supplies only the SDK's private marker method.
func newSpanView(original sdktrace.ReadOnlySpan) *spanView {
	return &spanView{context: original.SpanContext().WithTraceState(trace.TraceState{}), parent: original.Parent().WithTraceState(trace.TraceState{}), start: original.StartTime(), end: original.EndTime(), kind: original.SpanKind(), droppedAttributes: original.DroppedAttributes(), droppedEvents: original.DroppedEvents(), droppedLinks: original.DroppedLinks(), children: original.ChildSpanCount()}
}

// StartTime retains the original start timestamp.
func (s *spanView) StartTime() time.Time { return s.start }

// EndTime retains the original completion timestamp.
func (s *spanView) EndTime() time.Time { return s.end }

// SpanKind identifies the copied structural role.
func (s *spanView) SpanKind() trace.SpanKind { return s.kind }

// DroppedAttributes preserves the SDK's preexisting loss count.
func (s *spanView) DroppedAttributes() int { return s.droppedAttributes }

// DroppedEvents preserves the SDK's preexisting event loss count.
func (s *spanView) DroppedEvents() int { return s.droppedEvents }

// DroppedLinks preserves the SDK's preexisting link loss count.
func (s *spanView) DroppedLinks() int { return s.droppedLinks }

// ChildSpanCount retains the original child count.
func (s *spanView) ChildSpanCount() int { return s.children }

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

func maskSpan(ctx context.Context, scanner *embargo.Scanner, original sdktrace.ReadOnlySpan) (sdktrace.ReadOnlySpan, error) {
	view := newSpanView(original)
	view.name = original.Name()
	view.events = slices.Clone(original.Events())
	view.links = slices.Clone(original.Links())
	view.status = original.Status()
	view.scope = original.InstrumentationScope()
	var err error
	if view.attrs, err = maskAttributes(ctx, scanner, original.Attributes()); err != nil {
		return nil, err
	}
	for i := range view.events {
		if maskErr := maskTextFields(ctx, scanner, &view.events[i].Name); maskErr != nil {
			return nil, maskErr
		}
		if view.events[i].Attributes, err = maskAttributes(ctx, scanner, view.events[i].Attributes); err != nil {
			return nil, err
		}
	}
	for i := range view.links {
		view.links[i].SpanContext = view.links[i].SpanContext.WithTraceState(trace.TraceState{})
		if view.links[i].Attributes, err = maskAttributes(ctx, scanner, view.links[i].Attributes); err != nil {
			return nil, err
		}
	}
	schema := original.Resource().SchemaURL()
	if maskErr := maskTextFields(ctx, scanner, &view.name, &view.status.Description, &schema, &view.scope.Name, &view.scope.Version, &view.scope.SchemaURL); maskErr != nil {
		return nil, maskErr
	}
	attrs, err := maskAttributes(ctx, scanner, original.Resource().Attributes())
	if err != nil {
		return nil, err
	}
	view.resource = resource.NewWithAttributes(schema, attrs...)
	attrs, err = maskAttributes(ctx, scanner, view.scope.Attributes.ToSlice())
	if err != nil {
		return nil, err
	}
	view.scope.Attributes = attribute.NewSet(attrs...)
	return view, nil
}
