// Package embargootel wraps OpenTelemetry log and span exporters at the export boundary.
// Log bodies, attributes, event names and severity text are masked on copies. Records
// with sensitive immutable resource or scope fields become safe diagnostics.
// Span attributes, events, links, status, resource and scope fields are copied and masked.
// Trace and span IDs remain correlation identifiers. Exporters added outside these
// wrappers, binary encodings and custom downstream fields need separate checks.
//
// If masking fails, the adapter writes a fixed diagnostic with the time, level and
// an attribute count instead of the original fields; the logging guide explains it:
// https://nao1215.github.io/embargo/getting-started/#bounds-and-failures.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargootel
