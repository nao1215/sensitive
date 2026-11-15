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

embargo finds secrets and personal data in the output of Go programs, masks them in logs and JSON, and fails your tests when one leaks.

- Mask slog, zap, zerolog and logrus output and keep its JSON structure.
- Catch values nobody marked as secret: passwords in database URLs, API tokens, card numbers, emails, My Number.
- Keep a value out of every formatter with `Secret[T]`, and out of API responses with `MaskJSON`.
- Fail tests when a canary reaches stdout, stderr, logs, HTTP responses or child processes.

## Quick start

Requires Go 1.26.11 or later.

```sh
go get github.com/nao1215/embargo@latest
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

Mask everything a scanner finds, or keep part of a value:

<!-- masking:start -->
| Operation | Actual text |
|---|---|
| Input | `INFO checkout email=alice@example.com card=4111111111111111` |
| [Mask](masking_example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]` |
| [MaskFunc: keep last four](masking_example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]1111` |
| [Overlapping matches](masking_example_test.go) | `token=abcdef` with `abcd cdef` → `token=[REDACTED]` |
<!-- masking:end -->

[Scanner options and custom replacements](doc/masking.md)

## Catch what nobody declared

Field rules only hide the fields someone listed. embargo also reads the text, so a password inside a connection string is masked without any rule.

<!-- example: credential_example_test.go:ExampleKindCredential -->
```go
text := "postgres://reader:forgotten@db.example/orders"
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
// Output: postgres://reader:[REDACTED]@db.example/orders
```

| Group | What is detected |
|---|---|
| Credentials | URL and DSN passwords, `password=` and auth headers, provider tokens, JWT, PEM keys |
| Payment | Card numbers (Luhn), CVV, expiry, IBAN, SWIFT/BIC, ABA routing, UK sort code, bank account, ACH trace, merchant ID, payment tokens, Bitcoin and Ethereum addresses |
| Personal | Email, IP address, Japanese phone numbers and My Number, including full-width digits |

[Every detector and how it validates](doc/detectors.md) · [Provider token formats](doc/credentials.md)

Select only the kinds you need. On the same 2.7 KB of clean text, `WithKinds(KindEmail)` takes 0.11 µs and `WithAll()` takes 85 µs, and fewer kinds also mean fewer false positives. [Per-detector benchmarks](doc/benchmarks.md)

## Mask logs

`next` is the handler your logger already uses.

<!-- example: slog_example_test.go:ExampleNewSlogHandler_short -->
```go
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
logger := slog.New(embargo.NewSlogHandler(next, scanner))

logger.Info("checkout", "email", "alice@example.com")

// Output: {"level":"INFO","msg":"checkout","email":"[REDACTED]"}
```

Structs, maps and slices stay JSON objects and arrays, and values under keys such as `password`, `token` or `authorization` are masked whole. Messages, keys and group names are scanned too. [Structured values and key rules](doc/logging.md)

| Logger | Adapter example | Output excerpt |
|---|---|---|
| zap | [NewWriteSyncer](adapters/zap/example_test.go) | `"email":"[REDACTED]"` |
| zerolog | [NewWriter](adapters/zerolog/example_test.go) | `"email":"[REDACTED]"` |
| logrus | [NewFormatter](adapters/logrus/example_test.go) | `"email":"[REDACTED]"` |

The adapters apply the same detectors and key rules to the encoded JSON. [Installation and limits](doc/adapters.md)

## Values that must never print

<!-- example: secret_example_test.go:ExampleNewSecret -->
```go
key := embargo.NewSecret("fake-key")

fmt.Println(key)

// Output: [REDACTED]
```

`Secret` prints `[REDACTED]` through fmt, encoding/json, encoding/xml, text marshaling, templates and slog; `Reveal()` is the one way back. `Input` loads secrets from JSON, config files and SQL rows. Teams that keep their own types can follow a [standard-library-only pattern](doc/values.md) and check it with `embargotest.CheckValue`, which fails on the first output path that prints the value.

## Prove nothing leaks

One line guards every test in a package:

`func TestMain(m *testing.M) { os.Exit(embargotest.Guard(m)) }`

Guard reruns the package tests, scans their stdout, stderr, default slog output and child processes, and fails the run when a canary or a detected value appears. [ExampleGuard](embargotest/injection_example_test.go)

For one test, a recorder checks both that the expected output exists and that no canary escaped:

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

[HTTP, child processes, and canaries in env, files and headers](doc/testing-output.md)

## Measured

- In a sample service with planted leaks (a DSN, wrapped and joined errors, an Authorization header, a token in a request body), embargo's slog and zap paths masked every leak that reached a logger. A redirect URL never reaches a logger; `embargotest.HTTP` catches it. [Scenario table](doc/comparison.md#service-leak-scenarios)
- The same slog events through masq v0.2.3 and embargo: embargo took 52–78% less time on four of five events and allocated less on all five; the map event showed no significant difference. [Comparison](doc/comparison.md) · [benchstat](doc/comparison.benchstat.txt)

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
| [OTel SDK](https://github.com/nao1215/embargo/blob/main/tests/telemetry_integration_test.go#L26-L114) | `{"Key":"key","Value":{"Type":"STRING","Value":"[REDACTED]"}}` |
| [Sentry](https://github.com/nao1215/embargo/blob/main/tests/sentry_integration_test.go#L69-L152) | `"signing":{"key":"[REDACTED]"}` |
| [HTTP](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L120-L142) | `[REDACTED]` |
| [Child panic](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L144-L154) | `panic: [REDACTED]` |
<!-- tested-outputs:end -->

[Complete integration checks](tests/README.md).

## Accuracy

This chart shows the held-out synthetic set at the default minimum confidence of 0. [Generation, test cases and observed misses](doc/accuracy.md) explain the scores; [credential detectors](doc/credentials-accuracy.md) are measured separately.

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
Coverage 94.9% · mutation score 90.06% · 9 fuzz targets, 2323625 executions.
<!-- testing-metrics:end -->

[Commands, measurement scope and conditions](doc/testing.md).

## Benchmarks

<!-- benchmarks:start -->
![Scanner throughput and slog time](doc/images/benchmarks.svg)

All detectors scan sensitive text at 4.76 MB/s; masking a clean slog event takes 2.57 µs, 2.9× the plain handler.
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
