// Package embargogrpc adds masked server access records to unary and streaming RPCs.
// Install the interceptors on grpc.NewServer with the same scanner used for other logs.
// Incoming metadata and final error text are logged; messages and outgoing metadata are
// not recorded. Service inputs, status codes, error details and wire bytes are untouched.
// Scanner failures suppress the access record. Later logger additions need their own check.
package embargogrpc
