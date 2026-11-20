---
description: embargo masks secrets and personal data in Go logs, error reports, HTTP access logs and traces, and its command masks the output of any program. The root module has no dependencies.
---

embargo keeps secrets and personal data out of what a Go program writes: logs, error reports, HTTP access logs and traces. It works inside the application, where the value is written, and the root module has no dependencies outside the standard library. The `embargo` command masks the output of any program.

## Try it

<!-- example: example_test.go:ExampleNewSlogHandler_quickStart -->
```go
// next is the handler you already use, such as slog.NewJSONHandler(os.Stdout, nil).
logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner()))

logger.Info("login failed", "email", "alice@example.com", "password", "hunter2", "request_id", "req-7f3a")

// Output: {"level":"INFO","msg":"login failed","email":"[REDACTED]","password":"[REDACTED]","request_id":"req-7f3a"}
```

<!-- cli-example: e2e/atago/cli.atago.yaml -->
```text
$ printf '%s\n' 'login failed for alice@example.com from 203.0.113.7' | embargo
login failed for [REDACTED] from [REDACTED]
```

## What it is for

| You need to | Use |
|---|---|
| Keep a known secret, such as an API key, from ever printing | [`Secret`](/getting-started/#values-that-must-never-print) |
| Log the structs, errors and JSON you already have | [The slog handler and `MaskJSON`](/getting-started/#mask-slog-output), plus [adapters](/getting-started/#loggers-and-services) for zap, zerolog, logrus, gRPC, OpenTelemetry and Sentry |
| Catch secrets nobody declared, such as a card number inside an error message | [39 built-in detectors](/kinds/) |
| Mask a log you already have, or the output of a program you cannot change | [The `embargo` command](/command-line/) |
| Prove in CI that no secret reaches the output | [`embargotest`](/getting-started/#fail-tests-on-leaks) |

Redaction in a log pipeline can still run after it; embargo stops the leak where it is written. [Compare](/compare/) shows what other Go libraries and embargo catch on the same service output, what neither catches, and the speed of each.
