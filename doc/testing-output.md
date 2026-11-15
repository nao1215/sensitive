# Checking real output

A canary is a distinctive fake secret placed in the application path being tested. The recorder searches captured bytes for that value and its supported encodings, independently of detector findings. The [README test](../readme_output_test.go) shows a Secret passing through a real JSON logger.

## Connect the output boundary

| Producer | Connect to | Tested output |
|---|---|---|
| Logger or encoder | `recorder.Writer("logs")` | [Real loggers and encoders](../tests/compatibility_integration_test.go) |
| HTTP handler | `recorder.HTTP("http")` | [Status, headers, body, trailers and interim responses](../tests/http_integration_test.go) |
| Test-binary child | `recorder.Run(ctx, "TestHelper", exitCode)` | [stdout, stderr, panic and cleanup](../tests/lifecycle_test.go) |

## Require useful content

Register `Expect` or `ExpectJSON` before `Check`. A recorder with no output, missing expectations, incomplete capture or leaked values fails. Stop producers before checking; cleanup also checks supported late writes and trailer mutations.

[Recorder tests](../embargotest/recorder_test.go), [JSON expectations](../embargotest/json_test.go).

## Choose detector and fixture policy

The default scanner enables every built-in detector. `WithScanner` narrows it, while `WithAllowedKinds` and `WithAllowedValues` allow deliberate fixture content. Canary checks remain active even when a detector finding is allowed.

[Options and limits](../embargotest/recorder.go), [allowlist tests](../embargotest/recorder_test.go).

[Support maintenance](https://github.com/sponsors/nao1215).
