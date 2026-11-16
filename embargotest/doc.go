// Package embargotest records application outputs and checks them for a fake
// secret, configured detector findings and expected content.
//
// # Canary representations
//
// Check finds the canary as raw bytes, lower and upper case hex, padded and
// unpadded standard and URL base64, JSON with and without HTML escaping, Go
// quoting with and without ASCII escaping (%q and %+q), a decimal byte slice and
// a big-endian decimal integer, also when it is split across writes.
// WithCanaryFragments opts into raw contiguous pieces of at least 16 bytes.
// Smaller or derived values, mixed encodings, base64 shifted inside a larger
// blob and compressed or binary exports need their own decoding before they
// are written to a Recorder.
//
// The Recorder does not sanitize captured data. Connect every relevant output,
// stop producers and flush SDKs before calling Check.
//
// # HTTP
//
// Recorder.HTTP returns a bounded ResponseWriter with Flusher support. It starts no
// handler or goroutine. Stop the handler before Check; Header has the usual
// http.ResponseWriter map concurrency rules. Expect uses name/body, /headers,
// /trailers and /status. Headers and trailers are JSON objects of string arrays;
// status is decimal text. Four of the sixteen sink slots are used per response.
// Hijacker and Pusher are intentionally absent. This records handler output,
// not a server's wire encoding or arbitrary middleware outside this writer.
//
// # Child processes
//
// Recorder.Run executes a named top-level Test helper in the current test executable.
// The helper must guard its body with EMBARGO_TEST_CHILD == its name; the fake
// canary is base64 in EMBARGO_TEST_CANARY. No parent application environment is
// inherited. Output appends to stdout and stderr sinks, including -test.v's
// start marker, which proves a matching test ran. Set content expectations too.
//
// The earlier of ctx's deadline and WithLimits' timeout supervises the child.
// Cancel kills the direct child; Wait joins os/exec's pipe-copy and watcher
// goroutines before return. WaitDelay bounds pipes held open after child exit.
// Helpers must not create unmanaged descendants. Cancellation, timeouts,
// unexpected exits and incomplete pipes fail Check. Returned errors are fixed
// messages or context sentinels; they never carry child output.
package embargotest
