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

## Keep an existing masker and check the real application output

embargotest does not require replacing a team's logger or masker. In [TestExistingMaskerOutputCheck](../tests/comparison_libraries_test.go), the application writes a real JSON event through either a plain slog handler or masq configured with email/card regexes and field rules. An email in an attribute key remains visible in both original paths, and the recorder's Check fails. Wrapping that same handler in NewSlogHandler makes the test pass. The test records the expected failure in a test observer, so the repository suite itself stays green while proving both outcomes.

The same test uses the existing `Expect` callback to compare compact captured JSON with `scanner.MaskJSON(data)`, ensuring opaque values under sensitive keys are masked as well as detector-recognized text. For NDJSON, apply that comparison separately to each record. `WithScanner` alone checks text detectors and does not infer key rules. Teams can fix their existing masker instead of adding a wrapper and retain the same output assertions; a matching snapshot or JSON expectation should also confirm useful diagnostic fields survived.
