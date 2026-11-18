// Package embargosentry masks complete Sentry events at the BeforeSend boundary.
// Assign NewBeforeSend to ClientOptions.BeforeSend. Errors and panics during
// event serialization or scanning emit a safe diagnostic. Attachments and envelopes
// added after this callback are outside this boundary; configure them separately.
//
// If masking fails, the adapter writes a fixed diagnostic with the time, level and
// an attribute count instead of the original fields; the logging guide explains it:
// https://github.com/nao1215/embargo/blob/main/doc/logging.md#bounds-and-failures.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargosentry
