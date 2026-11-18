// Package embargozap masks JSON output from zap using an explicit embargo
// scanner. It is a separate module so the root library has no SDK dependencies.
//
// # JSON output and limits
//
// NewWriteSyncer masks newline-delimited JSON from a zap JSON encoder after all
// fields, With values, objects and arrays have been encoded. Both dependencies
// are required. Each event is bounded to 1 MiB and 64 nesting levels; malformed
// or incomplete JSON becomes a fixed diagnostic. Sync sends that diagnostic, synchronizes next even on framing failure, and joins both errors.
//
// Cumulative scanner input, including repeated field names, is limited to 4 MiB
// per event; exceeding it fails closed.
//
// Use this sink for every core that needs masking. Console/CBOR encoders are not
// supported. Base64 Binary fields and application encodings are not decoded;
// wrap such values in embargo.Secret before logging. Zap's separate ErrorOutput
// and any other sinks are outside this adapter's scope.
//
// If masking fails, the adapter writes a fixed diagnostic with a recognized level and
// an attribute count instead of the original fields; the logging guide explains it:
// https://github.com/nao1215/embargo/blob/main/doc/logging.md#bounds-and-failures.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargozap
