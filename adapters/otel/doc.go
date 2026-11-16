// Package embargootel wraps OpenTelemetry log and span exporters at the export boundary.
// Log bodies, attributes, event names and severity text are masked on copies. Records
// with sensitive immutable resource or scope fields are rejected rather than forwarded.
// Span attributes, events, links, status, resource and scope fields are copied and masked.
// Trace and span IDs remain correlation identifiers. Exporters added outside these
// wrappers, binary encodings and custom downstream fields need separate checks.
package embargootel
