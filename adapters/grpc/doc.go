// Package embargogrpc adds masked server access records to unary and streaming RPCs.
// Install the interceptors on grpc.NewServer with the same scanner used for other logs.
// Incoming metadata and final error text are logged; messages and outgoing metadata are
// not recorded. Service inputs, status codes, error details and wire bytes are untouched.
// Scanner failures emit a safe diagnostic record. Attributes already bound to the
// logger's handler, as with logger.With, are written as they are, and so is anything
// a later handler adds; build the logger from a handler without them.
//
// If masking fails, the adapter writes a fixed diagnostic with the time, level and
// an attribute count instead of the original fields; the logging guide explains it:
// https://github.com/nao1215/embargo/blob/main/doc/logging.md#bounds-and-failures.
// MarshalJSON, LogValue, String and Error can run before byte limits apply; their
// time and memory are not bounded. Prefer Secret or a bounded LogValuer.
package embargogrpc
