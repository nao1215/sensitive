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

- `postgres://reader:forgotten@db.example` in a log line becomes `postgres://reader:[REDACTED]@db.example` without any field rule.
- slog, zap, zerolog and logrus keep their JSON shape; only the values change.
- `embargo.NewSecret(key)` prints `[REDACTED]` wherever it is formatted.
- A test fails when a fake secret planted in your code shows up in its output.

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

## Detect without rules

The scanner reads the text itself, so no field has to be listed first.

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
| Cards | Card numbers (Luhn), CVV, expiry, payment tokens, merchant ID |
| Bank | IBAN, SWIFT/BIC, ABA routing, UK sort code, bank account, ACH trace |
| Crypto | Bitcoin and Ethereum addresses |
| Personal | Email, IP address, Japanese phone numbers and My Number, including full-width digits |

[Every detector and how it validates](doc/detectors.md) · [Provider token formats](doc/credentials.md)

Pick the kinds you need: on 2.7 KB of log lines with no secret, `WithKinds(KindEmail)` returns in 0.11 µs because there is no `@` to inspect, while `WithAll()` takes 85 µs. [Per-detector benchmarks](doc/benchmarks.md)

## Mask logs

`next` is the handler your logger already uses.

<!-- example: slog_example_test.go:ExampleNewSlogHandler_short -->
```go
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
logger := slog.New(embargo.NewSlogHandler(next, scanner))

logger.Info("checkout", "email", "alice@example.com")

// Output: {"level":"INFO","msg":"checkout","email":"[REDACTED]"}
```

Values under keys such as `password`, `token` or `authorization` are masked whole, and structs and maps stay JSON objects. [Structured values and key rules](doc/logging.md)

zap ([NewWriteSyncer](adapters/zap/example_test.go)), zerolog ([NewWriter](adapters/zerolog/example_test.go)) and logrus ([NewFormatter](adapters/logrus/example_test.go)) get the same detectors and key rules through optional modules. [Installation and limits](doc/adapters.md)

## Values that must never print

<!-- example: secret_example_test.go:ExampleNewSecret -->
```go
key := embargo.NewSecret("fake-key")

fmt.Println(key)

// Output: [REDACTED]
```

`key.Reveal()` returns the value. [Tested outputs](#tested-outputs) lists every path checked to print `[REDACTED]`.

`Input` loads secrets from JSON, config files and SQL rows.

Prefer your own types? Follow the [standard-library-only pattern](doc/values.md) and check them with `embargotest.CheckValue`.

## Fail tests on leaks

`func TestMain(m *testing.M) { os.Exit(embargotest.Guard(m)) }`

Guard reruns the package tests and fails when a canary (a fake secret) or a detected value appears in stdout, stderr, default slog output or child processes. [ExampleGuard](embargotest/injection_example_test.go)

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

In a sample service with planted leaks (a DSN, wrapped errors, an Authorization header, a token in a request body), the slog and zap paths masked every leak that reached a logger. The redirect URL never reaches a logger; `embargotest.HTTP` catches it. [Scenario table](doc/comparison.md#service-leak-scenarios)

## Tested outputs

Each link opens the test that produces and checks the shown output.

<!-- tested-outputs:start -->
| Output | Actual output (excerpt for SDKs) |
|---|---|
| [fmt](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L38-L38) | `embargo.Secret[string]([REDACTED])` |
| [slog TextHandler](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L39-L42) | `level=INFO msg=event token=[REDACTED] nested.again=[REDACTED]` |
| [slog JSONHandler](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L43-L46) | `{"level":"INFO","msg":"event","token":"[REDACTED]","nested":{"again":"[REDACTED]"}}` |
| [encoding/json](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L47-L47) | `"[REDACTED]"` |
| [encoding/xml](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L48-L53) | `<record><token>[REDACTED]</token></record>` |
| [text/template](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L54-L60) | `[REDACTED]` |
| [zap JSON core](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L61-L67) | `{"level":"info","msg":"event","token":"[REDACTED]"}` |
| [zerolog JSON](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L68-L72) | `{"level":"info","token":"[REDACTED]","message":"event"}` |
| [logrus JSON](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L73-L79) | `{"level":"info","msg":"event","token":"[REDACTED]"}` |
| [OTel SDK](https://github.com/nao1215/embargo/blob/main/tests/telemetry_integration_test.go#L26-L114) | `{"Key":"key","Value":{"Type":"STRING","Value":"[REDACTED]"}}` |
| [Sentry](https://github.com/nao1215/embargo/blob/main/tests/sentry_integration_test.go#L74-L157) | `"signing":{"key":"[REDACTED]"}` |
| [HTTP](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L120-L142) | `[REDACTED]` |
| [Child panic](https://github.com/nao1215/embargo/blob/main/tests/compatibility_integration_test.go#L144-L154) | `panic: [REDACTED]` |
<!-- tested-outputs:end -->

[Complete integration checks](tests/README.md).

## Accuracy

Held-out synthetic set, default minimum confidence 0. [Generation, test cases and observed misses](doc/accuracy.md) · [Credential detectors](doc/credentials-accuracy.md), measured separately

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

<!-- real-logs-summary:start -->
![Estimated false positives on public logs](doc/images/real-logs.svg)

Round 13: 8 public datasets, 92.4 MB, 819,576 lines. [Licenses, classification rules, per-kind and per-configuration FP/GB](doc/accuracy.md#public-system-logs). Rates are sample estimates; contact and endpoint references count as sensitive data, and no recall claim is made.
<!-- real-logs-summary:end -->

## Testing

| Technique | Tests |
|---|---|
| Examples and unit tests | [Examples](example_test.go), [masking](tests/mask_test.go) |
| Generated properties | [Properties](tests/properties_test.go), [Bitcoin](tests/bitcoin_test.go) |
| Fuzzing | [Scanner](fuzz_test.go), [recorder](embargotest/fuzz_test.go) |
| Mutation | [gremlins command](Makefile) |
| Real output tests | [Loggers](tests/compatibility_integration_test.go), [HTTP](tests/http_integration_test.go) |

<!-- testing-metrics:start -->
Coverage 97.1% · mutation score 88.26% · 9 fuzz targets, 2388415 executions.
<!-- testing-metrics:end -->

[Commands, measurement scope and conditions](doc/testing.md).

## Benchmarks

<!-- benchmarks:start -->
![Scanner throughput and slog time](doc/images/benchmarks.svg)

All detectors scan sensitive text at 4.89 MB/s; masking a clean slog event takes 2.48 µs, 2.9× the plain handler.
<!-- benchmarks:end -->

<!-- narrowing-summary:start -->
Round 13 scanner medians (ten interleaved samples):

| Selection | Clean ns/op | Dirty ns/op | Clean / dirty speedup over WithAll |
|---|---:|---:|---|
| all | 60,274.000 | 6,487,012.0 | 1.00× / 1.00× |
| kinds1 | 96.955 | 38,425.5 | 621.67× / 168.82× |
| kinds3 | 14,700.500 | 598,465.0 | 4.10× / 10.84× |
| kinds8 | 17,402.000 | 2,790,511.5 | 3.46× / 2.32× |

[kinds1/3/8 definitions, input sizes and uncertainty](doc/benchmarks.md#choose-the-kinds-the-application-needs). Narrower selection avoids irrelevant detections and gives up their recall.
<!-- narrowing-summary:end -->

[Machine, method, profiles and full results](doc/benchmarks.md).

Same slog events through masq v0.2.3: 22–78% less time and fewer allocations on all five events. [Comparison](doc/comparison.md) · [benchstat](doc/comparison.benchstat.txt)

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
