# Masking slog output

Pass a downstream handler and an explicit scanner to `NewSlogHandler`. Messages, attribute keys, group names and values are scanned before forwarding. The [runnable Examples](../slog_example_test.go) show text and JSON output; [structured Examples](../structured_example_test.go) show the shared JSON policy.

## Keep the logger's JSON shape

Nested fields such as `user.id`, `order.amount` and `error.code` remain queryable by Loki, Datadog, CloudWatch and BigQuery. Objects stay objects, arrays stay arrays, and clean numeric values keep their number type and precision, so existing field filters and range queries continue to work.

| Value | Forwarded representation |
|---|---|
| Clean string or scalar | Original scalar type |
| Sensitive string | Only sensitive spans replaced |
| Sensitive numeric value | Marker string, preserving the existing detector contract |
| Matching sensitive key or group | Entire value replaced with `[REDACTED]` |
| Group | Sanitized names and recursively sanitized values |
| LogValuer | Resolved value, then sanitized; at most 100 resolutions |
| Any | Encoded JSON with masked leaves and keys, forwarded as raw JSON |
| error, including wrapped errors | Scanned `Error()` text, never an empty JSON object |

Scalars and errors use the original attribute key as detector context, including values resolved by LogValuer and attached by WithAttrs. Duration is checked as both nanoseconds and duration text; float values use both JSON decimal/exponent encoding and text encoding; time values use both RFC3339Nano and the TextHandler millisecond layout. A match in either representation prevents the original typed value from reaching either handler.

The Any path uses `encoding/json` before masking, as `slog.JSONHandler` does. JSON tags, `json:"-"`, `omitempty`, custom `MarshalJSON`, and unexported-field visibility therefore retain their normal behavior. A `fmt.Stringer` does not override JSON encoding. Nested `LogValuer` methods are not called by `encoding/json`, as they are not called by an unwrapped JSONHandler; their exported JSON fields are scanned instead. Nested `Secret` values mask themselves through `MarshalJSON`. TextHandler displays structured Any values as compact JSON text, with its normal quoting; errors remain readable text.

The shared engine validates the whole document with `encoding/json.Valid`, then walks its values, decodes escaped strings with `encoding/json`, and retains the original numeric lexemes (the precision guarantee of `UseNumber`). This avoids materializing a map tree and preserves duplicate keys and their order. Profiling found Decoder.Token to be an allocation hot spot, so the validated byte walk replaces the original token walker; JSON semantics are checked differentially against encoding/json by FuzzJSONShape. All values under duplicate keys are visited. Masked keys can collide, so consumers must not interpret the result as an authorization policy or a lossless identifier mapping. The same engine protects the encoded output of the [zap, zerolog and logrus adapters](adapters.md), and `Scanner.MaskJSON` sanitizes API responses, audit exports and support bundles outside logging. This returns bytes, not a copy of the original Go type.

## One key policy

By default, the values of `password`, `passwd`, `secret`, `token`, `api_key`, `authorization`, `cookie` and `set-cookie` are hidden, including whole objects, arrays, booleans and nulls. Matching ignores ASCII case and `_`, `-`, `.` and space: `apiKey` and `API-KEY` match `api_key`. Match names as they appear after JSON encoding; a struct field renamed by a JSON tag uses the JSON name. This is exact normalized matching, not prefix or substring matching.

`WithSensitiveKeys(names...)` replaces that set; include the default names along with additional names to extend it, or pass no names to disable it. Scanner options apply in order and copy the configured names. A matching `WithGroup` replaces the whole group with a marker and suppresses its descendant attributes; attributes attached before that group remain intact. See the [runnable option Example](../structured_example_test.go).

Key rules apply to structured output, not arbitrary text in `Scanner.Scan`. Existing `embargotest.Expect` can compare captured JSON with `scanner.MaskJSON` to enforce the identical policy; `WithScanner` alone checks detector findings. See the [application output regression](../tests/comparison_libraries_test.go).

## Why a Handler, rather than another ReplaceAttr

`ReplaceAttr` is convenient when an application already configures HandlerOptions, and those options can still be set on the downstream handler. However, slog does not pass group attributes through ReplaceAttr, and its `groups` argument cannot rename group names. A Handler can freeze sanitized `WithAttrs` values, sanitize messages and keys, suppress sensitive groups, and return a fixed error when normalization fails. A second callback API would offer weaker guarantees under a similar name, so embargo keeps one Handler API.

Attributes passed through `With` are sanitized and frozen at that call. Context, timestamp, level and source metadata are preserved. Downstream ReplaceAttr callbacks and custom handlers can introduce new data after embargo; test the actual sink when using them.

## Bounds and failures

Each encoded Any document is limited to 1 MiB input/output, depth 64 and 4 MiB cumulative detector input, including repeated key context. Explicit slog groups and WithGroup chains share depth 64. Scalar record attributes have no record-wide byte limit; the encoded logger adapters have a 1 MiB event limit including the newline. The JSON limits apply after `encoding/json` returns and cannot bound allocations or work performed inside caller-controlled MarshalJSON, Error or LogValue methods.

Invalid JSON, cycles or unsupported values during encoding, exceeded bounds, scanner panics and normalization panics drop the record and return a fixed error without the original value. Ordinary `slog.Logger` calls discard handler errors; call `Handler.Handle` directly when the result is part of an application contract. A downstream sink error is returned unchanged.

[Failure, concurrency and scalar tests](../slog_handler_test.go), [shape and boundary tests](../structured_test.go), [measurements against masq](comparison.md).

[Support maintenance](https://github.com/sponsors/nao1215).
