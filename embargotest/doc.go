// Package embargotest records application outputs and checks them for a fake
// secret and for the fields a test expects, such as a failure code.
//
// Check finds the canary as raw bytes, lower and upper case hex, padded and
// unpadded standard and URL base64, JSON with and without HTML escaping, Go
// quoting with and without ASCII escaping (%q and %+q), a decimal byte slice and
// a big-endian decimal integer, also when it is split across writes.
// Partial or derived values, mixed encodings, base64 shifted inside a larger
// blob and compressed or binary exports need their own decoding before they
// are written to a Recorder.
//
// The Recorder does not sanitize captured data. Connect every relevant output,
// stop producers and flush SDKs before calling Check.
package embargotest
