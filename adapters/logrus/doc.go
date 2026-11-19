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
// A byte slice, which logrus writes as base64, is decoded once and scanned when it
// is 20 bytes to 8 KiB of padded standard base64 and decodes to printable text;
// other binary data and application encodings are not decoded, so wrap such
// values in embargo.Secret before logging. Hooks with independent output are
// outside the formatter boundary. The caller's formatter must be safe for the
// logger's concurrency configuration; the adapter does not mutate the Entry.
//
// If masking fails, the adapter writes a fixed diagnostic with the time, level and
// an attribute count instead of the original fields; the logging guide explains it:
// https://github.com/nao1215/embargo/blob/main/doc/logging.md#bounds-and-failures.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargologrus
