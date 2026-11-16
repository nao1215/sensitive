// Package embargootel wraps OpenTelemetry log and span exporters at the export boundary.
// Log bodies, attributes, event names and severity text are masked on copies. Records
// with sensitive immutable resource or scope fields become safe diagnostics.
// Span attributes, events, links, status, resource and scope fields are copied and masked.
// Trace and span IDs remain correlation identifiers. Exporters added outside these
// wrappers, binary encodings and custom downstream fields need separate checks.
//
// Failed masking emits time/level, a fixed withheld message and an attribute
// count, without original fields. See the logging guide for count definitions,
// byte-writer metadata limitations and cooperative cancellation budgets:
// https://github.com/nao1215/embargo/blob/main/doc/logging.md.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargootel
