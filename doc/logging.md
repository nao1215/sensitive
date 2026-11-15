# Masking slog output

Pass a downstream handler and an explicit scanner to `NewSlogHandler`. Messages, attribute keys, group names and values are scanned before forwarding. The [runnable Examples](../slog_example_test.go) show text and JSON output.

## What happens to values?

| Value | Forwarded representation |
|---|---|
| Clean string or scalar | Original scalar type |
| Sensitive string | Masked string |
| Sensitive numeric value | `[REDACTED]` as a string |
| Group | Sanitized names and recursively sanitized values |
| LogValuer | Resolved value, then sanitized |
| Any or error | One formatted and scanned string |

Attributes passed through `With` are sanitized and frozen at that call. Context, timestamp, level and source metadata are preserved. See [real handler tests](../slog_handler_test.go) and [value tests](../slog_handler_test.go).

## When output fails

Scanner or value-formatting panics drop the record and return a fixed error without the panic value. Ordinary `slog.Logger` calls discard handler errors; call `Handler.Handle` directly when the result is part of an application contract. A downstream handler that adds new sensitive data needs its own output check.

[Failure and concurrency tests](../slog_handler_test.go).

[Support maintenance](https://github.com/sponsors/nao1215).
