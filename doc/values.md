# Values that must not be displayed

`Secret` prints `[REDACTED]` through fmt, slog, JSON and text encoding, including XML's text-marshaling path. `Reveal` deliberately returns the wrapped value. The wrapper suppresses display; it does not erase memory or control a value after Reveal.

| Operation | Result |
|---|---|
| `fmt.Sprint(embargo.NewSecret("fake-key"))` | `[REDACTED]` |
| JSON encoding of that Secret | `"[REDACTED]"` |
| `secret.Reveal()` | `fake-key` |

See the [runnable Secret Examples](../secret_example_test.go) and [actual encoder tests](../tests/compatibility_integration_test.go).

## Decode before publishing a Secret

`Input[string]` decodes JSON strings or text; `Input[[]byte]` uses JSON's base64 convention for byte slices. `Secret()` returns a snapshot unaffected by later decoding into the Input. Its decoding errors clear the stored value, including a rejected redaction marker.

Decode into a fresh object: absent fields and invalid outer JSON can prevent Input's decoder from being called. The [outer-object regression](../tests/input_lifecycle_test.go) demonstrates why reusing a populated object can retain an earlier value.

[Decoding contracts and regressions](../input_test.go), [Input Examples](../secret_example_test.go).

[Support maintenance](https://github.com/sponsors/nao1215).
