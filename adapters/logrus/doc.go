// Package embargologrus masks JSON output from logrus using an explicit embargo
// scanner. It is a separate module so the root library has no SDK dependencies.
//
// # JSON output and limits
//
// NewFormatter masks the complete JSON object returned by next, including
// messages, pre-bound fields, keys and nested values. Both dependencies are
// required. Use logrus.JSONFormatter or a formatter that returns one JSON object;
// text formatters, malformed output, events over 1 MiB and nesting over 64 levels
// fail closed. Formatting errors and panics become fixed errors without values.
//
// Byte slices encoded as base64 and other application encodings are not decoded;
// wrap them in embargo.Secret before logging. Hooks with independent output are
// outside the formatter boundary. The caller's formatter must be safe for the
// logger's concurrency configuration; the adapter does not mutate the Entry.
package embargologrus
