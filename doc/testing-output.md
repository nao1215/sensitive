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

## Keep an existing masker and check the real application output

embargotest does not require replacing a team's logger or masker. In [TestExistingMaskerOutputCheck](../tests/comparison_libraries_test.go), the application writes a real JSON event through either a plain slog handler or masq configured with email/card regexes and field rules. An email in an attribute key remains visible in both original paths, and the recorder's Check fails. Wrapping that same handler in NewSlogHandler makes the test pass. The test records the expected failure in a test observer, so the repository suite itself stays green while proving both outcomes.

The same test uses the existing `Expect` callback to compare compact captured JSON with `scanner.MaskJSON(data)`, ensuring opaque values under sensitive keys are masked as well as detector-recognized text. For NDJSON, apply that comparison separately to each record. `WithScanner` alone checks text detectors and does not infer key rules. Teams can fix their existing masker instead of adding a wrapper and retain the same output assertions; a matching snapshot or JSON expectation should also confirm useful diagnostic fields survived.

[Support maintenance](https://github.com/sponsors/nao1215).

## Guard an entire package

Put `func TestMain(m *testing.M) { os.Exit(embargotest.Guard(m)) }` in a test file. Guard re-executes the current test binary under a bounded supervisor and scans actual stdout and stderr before replaying safe output. This includes the default slog logger, verbose t.Log output, panics and subprocesses inheriting those descriptors. It does not mutate process-global writers or default loggers, and os/exec joins all capture workers. The test environment, working directory and original test arguments are preserved; verbose output is enabled in the child unless explicitly disabled with -test.v=false, which also hides passing t.Log output. Existing -test.v=test2json framing is preserved. Package initialization before TestMain and separately redirected subprocess output require separate checks.

The default cap is 1 MiB total and five minutes; use WithLimits for a larger suite. Timeout, output truncation and scanner failures fail the package. WithCanary, WithScanner and fixture allowances use the same policy as Recorder. The default scanner keeps confidence 0 and reports some public random identifiers as high-entropy candidates. To exclude that family, pass `WithScanner(embargo.NewScanner(embargo.WithMinConfidence(0.5)))`; this also loses all uncontextualized entropy detections. Prefer a narrow fixture allowance when the public value is known. See [measured threshold trade-offs](accuracy.md). The internal EMBARGO_PACKAGE_GUARD environment variable is reserved; setting it manually bypasses the supervisor. Reports name the stream and all tests observed in that process. Concurrent raw writes have no testing.T identity, so the list is a candidate set, not a claim that every listed test leaked. Stop background producers before a test completes. Existing TestMain side effects should be inside the guarded test lifecycle because TestMain executes in both parent and child.

Use Recorder.Setenv for environment input (testing restores it and rejects parallel tests), File for secret-file input, Header for HTTP headers, Reader for HTTP bodies/config parsers, and `string(r.Canary())` as a database row or SQL argument. The helpers return standard types and never require a domain wrapper. File uses a private temporary directory owned by testing cleanup. For structured config files, compose the document with Canary using the format's standard encoder.

The SDK integration module captures OTel spans, OTel logs and Sentry events in memory, including wrapped errors; HTTP checks include redirects and error bodies. Flush before Check, assert expected content, and scan the complete event. A missing or empty export is not evidence of successful masking. The package-guard fixture is tested with parallel writes, t.Log, panic and inherited child output; the tests/guardlifecycle package applies goleak to both supervisor and child on Linux, Windows and macOS CI.

## Static name check prototype

`TestSecretNameAnalyzerPrototype` runs a golang.org/x/tools/go/analysis prototype against real type-checked logger calls in the dependency-isolated tests module. It flags variables and fields called password, token or secret unless their type is embargo.Secret. The adversarial fixture yields two useful reports and three false positives: a complete homemade type, Input, and a logger already wrapped with embargo. An opaque variable name also bypasses the rule. That is 40% precision on this deliberately small counterexample set, not a production estimate. The analyzer is not shipped: recognizing arbitrary formatting and downstream handler configuration would require a larger analysis contract and would still not prove actual output. CheckValue and the output guard cover those cases through observed behavior.
