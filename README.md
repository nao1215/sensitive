# embargo

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg?style=flat-square)](#contributors)
<!-- ALL-CONTRIBUTORS-BADGE:END -->
[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/embargo.svg)](https://pkg.go.dev/github.com/nao1215/embargo)
[![MultiPlatformUnitTest](https://github.com/nao1215/embargo/actions/workflows/unit_test.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/unit_test.yml)
[![reviewdog](https://github.com/nao1215/embargo/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/reviewdog.yml)
[![Gosec](https://github.com/nao1215/embargo/actions/workflows/gosec.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/gosec.yml)
[![Trivy](https://github.com/nao1215/embargo/actions/workflows/trivy.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/trivy.yml)
![Coverage](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/embargo/coverage.svg)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/nao1215/embargo/badge)](https://scorecard.dev/viewer/?uri=github.com/nao1215/embargo)

<p align="center">
  <img src="doc/images/logo-small.png" alt="Go gopher peeking over the embargo title, with email and token values blacked out" width="320">
</p>

embargo detects and masks sensitive text in Go programs, logs and test output.

- Mask card numbers and emails before logs leave your service.
- Check in tests that an HTTP handler or child process never writes a secret.
- Scan support messages and imported files for personal data.
- Detect Japanese phone numbers and My Number, including full-width digits.

## Quick start

These examples use the unreleased API on main (Go 1.26.11 or later).

```sh
go get github.com/nao1215/embargo@main
```

<!-- example: example_test.go:Example -->
```go
package main

import (
	"fmt"

	"github.com/nao1215/embargo"
)

func main() {
	text := "email=alice@example.com card=4111111111111111"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))

	fmt.Println(embargo.Mask(text, scanner.ScanString(text)))

	// Output: email=[REDACTED] card=[REDACTED]
}
```

[Scanner options and custom detectors](doc/masking.md).

## Why embargo?

[gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog) scan repositories and files; [Presidio](https://presidio.dataprivacystack.org/) provides Python analyzers. Secret wrappers hide marked values without detecting sensitive text. embargo runs inside Go to mask logs, hide Secret values, and check real output with canaries and detectors.

| Inside your Go program | What happens |
|---|---|
| `NewSlogHandler` | `email=alice@example.com` → `email=[REDACTED]` |
| `NewSecret` | `fake-key` → `[REDACTED]` |
| `embargotest` | A canary in logs, HTTP or child output fails the test. |

[How the pieces fit](doc/runtime.md).

## Scanning and masking

<!-- masking:start -->
| Operation | Actual text |
|---|---|
| Input | `INFO checkout email=alice@example.com card=4111111111111111` |
| [Mask](masking_example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]` |
| [MaskFunc: keep last four](masking_example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]1111` |
| [Overlapping matches](masking_example_test.go) | `token=abcdef` with `abcd cdef` → `token=[REDACTED]` |
<!-- masking:end -->

[Scanner options, custom replacements and overlapping matches](doc/masking.md).

## Values that must not be displayed

Wrap a value with `Secret` before passing it to a logger or encoder.

<!-- example: secret_example_test.go:ExampleNewSecret -->
```go
key := embargo.NewSecret("fake-key")

fmt.Println(key)

// Output: [REDACTED]
```

[Formatting, decoding with Input, and deliberate access with Reveal](doc/values.md).

## Mask logs

`next` is the handler your logger already uses.

<!-- example: slog_example_test.go:ExampleNewSlogHandler_short -->
```go
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
logger := slog.New(embargo.NewSlogHandler(next, scanner))

logger.Info("checkout", "email", "alice@example.com")

// Output: {"level":"INFO","msg":"checkout","email":"[REDACTED]"}
```

[Full runnable example](slog_example_test.go) · [Groups, value handling and output failures](doc/logging.md).

## Logger adapters

| Logger | Adapter example | Output excerpt |
|---|---|---|
| zap | [NewWriteSyncer](adapters/zap/example_test.go) | `"email":"[REDACTED]"` |
| zerolog | [NewWriter](adapters/zerolog/example_test.go) | `"email":"[REDACTED]"` |
| logrus | [NewFormatter](adapters/logrus/example_test.go) | `"email":"[REDACTED]"` |

Each optional module masks the logger's encoded JSON, including nested values. [Installation, APIs and encoded-binary limits](doc/adapters.md).

## Check test output

A canary is a fake secret injected into the code under test. The recorder checks both that useful output exists and that canaries or detected values did not escape.

<!-- test: readme_output_test.go:TestReadmeCheckOutput -->
```go
func TestReadmeCheckOutput(t *testing.T) {
    t.Parallel()
    recorder := embargotest.New(t)
    logger := slog.New(slog.NewJSONHandler(recorder.Writer("logs"), nil))

    logger.Info("accepted", "token", embargo.NewSecret(recorder.Canary()))

    recorder.ExpectJSON("logs", nil, map[string]string{"token": "[REDACTED]"}, 1)
    recorder.Check()
}
```

Output includes `"token":"[REDACTED]"` and the test passes. [HTTP, child processes, expectations and allowed fixtures](doc/testing-output.md).

## Tested outputs

Each link opens the test that produces and checks the shown output.

<!-- tested-outputs:start -->
| Output | Actual output (excerpt for SDKs) |
|---|---|
| [fmt](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L38-L38) | `[REDACTED]` |
| [slog TextHandler](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L39-L42) | `level=INFO msg=event token=[REDACTED] nested.again=[REDACTED]` |
| [slog JSONHandler](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L43-L46) | `{"level":"INFO","msg":"event","token":"[REDACTED]","nested":{"again":"[REDACTED]"}}` |
| [encoding/json](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L47-L47) | `"[REDACTED]"` |
| [encoding/xml](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L48-L53) | `<record><token>[REDACTED]</token></record>` |
| [text/template](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L54-L60) | `[REDACTED]` |
| [zap JSON core](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L61-L67) | `{"level":"info","msg":"event","token":"[REDACTED]"}` |
| [zerolog JSON](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L68-L72) | `{"level":"info","token":"[REDACTED]","message":"event"}` |
| [logrus JSON](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L73-L79) | `{"level":"info","msg":"event","token":"[REDACTED]"}` |
| [OTel SDK](https://github.com/nao1215/embargo/blob/main/tests/telemetry_integration_test.go#L24-L103) | `{"Key":"key","Value":{"Type":"STRING","Value":"[REDACTED]"}}` |
| [Sentry](https://github.com/nao1215/embargo/blob/main/tests/sentry_integration_test.go#L67-L141) | `"signing":{"key":"[REDACTED]"}` |
| [HTTP](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L120-L142) | `[REDACTED]` |
| [Child panic](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L144-L154) | `panic: [REDACTED]` |
<!-- tested-outputs:end -->

[Complete integration checks](tests/README.md).

## Accuracy

This chart shows the held-out synthetic set at the default minimum confidence of 0. [Generation, test cases and observed misses](doc/accuracy.md) explain the scores.

<!-- accuracy:start -->
![Precision and recall on held-out synthetic samples](doc/images/accuracy.svg)

| Detector details | | |
|---|---|---|
| [aba_routing](doc/accuracy.md#aba-routing) | [ach_trace](doc/accuracy.md#ach-trace) | [awskey](doc/accuracy.md#awskey) |
| [bank_account](doc/accuracy.md#bank-account) | [btc](doc/accuracy.md#btc) | [card_expiry](doc/accuracy.md#card-expiry) |
| [cvv](doc/accuracy.md#cvv) | [email](doc/accuracy.md#email) | [eth](doc/accuracy.md#eth) |
| [github_token](doc/accuracy.md#github-token) | [google_api_key](doc/accuracy.md#google-api-key) | [iban](doc/accuracy.md#iban) |
| [ipaddr](doc/accuracy.md#ipaddr) | [jwt](doc/accuracy.md#jwt) | [merchant_id](doc/accuracy.md#merchant-id) |
| [mynumber](doc/accuracy.md#mynumber) | [pan](doc/accuracy.md#pan) | [payment_token](doc/accuracy.md#payment-token) |
| [phone_jp](doc/accuracy.md#phone-jp) | [private_key_pem](doc/accuracy.md#private-key-pem) | [slack_token](doc/accuracy.md#slack-token) |
| [swiftbic](doc/accuracy.md#swiftbic) | [uk_sortcode](doc/accuracy.md#uk-sortcode) | |
<!-- accuracy:end -->

## Testing

| Technique | Bugs it catches | Tests |
|---|---|---|
| Examples and unit tests | Wrong outputs and broken contracts | [Examples](example_test.go), [masking](tests/mask_test.go) |
| Generated properties | Checksum and boundary mistakes | [Properties](tests/properties_test.go), [Bitcoin](tests/bitcoin_test.go) |
| Fuzzing | Panics and broken input handling | [Scanner](fuzz_test.go), [recorder](embargotest/fuzz_test.go) |
| Mutation | Missing assertions | [gremlins command](Makefile) |
| Real output tests | Leaks after encoding or buffering | [Loggers](tests/compatibility_integration_test.go), [HTTP](tests/http_integration_test.go) |

<!-- testing-metrics:start -->
Coverage 96.8% · mutation score 90.68% · 7 fuzz targets, 2949231 executions.
<!-- testing-metrics:end -->

[Commands, measurement scope and conditions](doc/testing.md).

## Benchmarks

<!-- benchmarks:start -->
![Scanner throughput and slog time](doc/images/benchmarks.svg)

All detectors scan sensitive text at 9.89 MB/s; masking a clean slog event takes 2.26 µs, 2.7× the plain handler.
<!-- benchmarks:end -->

[Machine, method, profiles and full results](doc/benchmarks.md).

## Contributing

[Report a bug](https://github.com/nao1215/embargo/issues) → [add a synthetic regression](CONTRIBUTING.md) → open a pull request. You can also [sponsor maintenance](https://github.com/sponsors/nao1215).

## License

[MIT License](LICENSE).

The [Go gopher](https://go.dev/blog/gopher) was designed by [Renee French](https://reneefrench.blogspot.com/) and is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## Contributors

Thanks to our contributors:

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://debimate.jp/"><img src="https://avatars.githubusercontent.com/u/22737008?v=4?s=75" width="75px;" alt="CHIKAMATSU Naohiro"/><br /><sub>CHIKAMATSU Naohiro</sub></a><br /><a href="https://github.com/nao1215/embargo/commits?author=nao1215" title="Code">Code</a> <a href="https://github.com/nao1215/embargo/commits?author=nao1215" title="Documentation">Documentation</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification.
