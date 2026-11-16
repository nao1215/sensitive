// Package embargologrus masks JSON output from logrus using an explicit embargo
// scanner. It is a separate module so the root library has no SDK dependencies.
//
// # JSON output and limits
//
// NewFormatter masks the complete JSON object returned by next, including
// messages, pre-bound fields, keys and nested values. Both dependencies are
// required. Use logrus.JSONFormatter or a formatter that returns one JSON object;
// text formatters, malformed output, events over 1 MiB and nesting over 64 levels
// fail closed. Formatting errors and panics become diagnostics without original values.
//
// Cumulative scanner input, including repeated field names, is limited to 4 MiB
// per event; exceeding it fails closed.
//
// Byte slices encoded as base64 and other application encodings are not decoded;
// wrap them in embargo.Secret before logging. Hooks with independent output are
// outside the formatter boundary. The caller's formatter must be safe for the
// logger's concurrency configuration; the adapter does not mutate the Entry.
//
// Failed masking emits time/level, a fixed withheld message and an attribute
// count, without original fields. See the logging guide for count definitions,
// byte-writer metadata limitations and cooperative cancellation budgets:
// https://github.com/nao1215/embargo/blob/main/doc/logging.md.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargologrus
