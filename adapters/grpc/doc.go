// Package embargogrpc adds masked server access records to unary and streaming RPCs.
// Install the interceptors on grpc.NewServer with the same scanner used for other logs.
// Incoming metadata and final error text are logged; messages and outgoing metadata are
// not recorded. Service inputs, status codes, error details and wire bytes are untouched.
// Scanner failures emit a safe diagnostic record. Later logger additions need their own check.
//
// Failed masking emits time/level, a fixed withheld message and an attribute
// count, without original fields. See the logging guide for count definitions,
// byte-writer metadata limitations and cooperative cancellation budgets:
// https://github.com/nao1215/embargo/blob/main/doc/logging.md.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargogrpc
