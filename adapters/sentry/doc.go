// Package embargosentry masks complete Sentry events at the BeforeSend boundary.
// Assign NewBeforeSend to ClientOptions.BeforeSend. Errors and panics during
// event serialization or scanning emit a safe diagnostic. Attachments and envelopes
// added after this callback are outside this boundary; configure them separately.
//
// Failed masking emits time/level, a fixed withheld message and an attribute
// count, without original fields. See the logging guide for count definitions,
// byte-writer metadata limitations and cooperative cancellation budgets:
// https://github.com/nao1215/embargo/blob/main/doc/logging.md.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargosentry
