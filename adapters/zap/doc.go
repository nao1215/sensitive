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
// Failed masking omits unproven input timestamps and emits an allowlisted level, a fixed withheld message and an attribute
// count, without original fields. See the logging guide for count definitions,
// byte-writer metadata limitations and cooperative cancellation budgets:
// https://github.com/nao1215/embargo/blob/main/doc/logging.md.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargozap
