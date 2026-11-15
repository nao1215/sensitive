// Package embargozerolog masks JSON output from zerolog using an explicit embargo
// scanner. It is a separate module so the root library has no SDK dependencies.
//
// # JSON output and limits
//
// NewWriter masks newline-delimited JSON after zerolog has encoded every field,
// including fields set on a Context. Both dependencies are required. It buffers
// split events, limits each to 1 MiB and 64 nesting levels, and never forwards
// malformed, oversized or incomplete JSON. Close checks completeness and seals
// the adapter without closing the caller-owned sink; always check its error.
//
// Cumulative scanner input, including repeated field names, is limited to 4 MiB
// per event; exceeding it fails closed.
//
// Use the default JSON encoder. Binary/CBOR builds and ConsoleWriter before the
// adapter are unsupported and fail closed. Hex and other application encodings
// are not decoded; wrap values in embargo.Secret before encoding. Hooks cannot
// reliably rewrite already encoded fields, which is why this is a writer.
package embargozerolog
