# embargo

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg?style=flat-square)](#contributors)
<!-- ALL-CONTRIBUTORS-BADGE:END -->
[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/embargo.svg)](https://pkg.go.dev/github.com/nao1215/embargo)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/nao1215/embargo/total)](https://github.com/nao1215/embargo/releases)
[![MultiPlatformUnitTest](https://github.com/nao1215/embargo/actions/workflows/unit_test.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/unit_test.yml)
[![reviewdog](https://github.com/nao1215/embargo/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/reviewdog.yml)
[![Gosec](https://github.com/nao1215/embargo/actions/workflows/gosec.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/gosec.yml)
[![Trivy](https://github.com/nao1215/embargo/actions/workflows/trivy.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/trivy.yml)
![Coverage](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/embargo/coverage.svg)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/nao1215/embargo/badge)](https://scorecard.dev/viewer/?uri=github.com/nao1215/embargo)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

<p align="center">
  <img src="doc/images/logo-small.png" alt="Go gopher peeking over the embargo title, with email and token values blacked out" width="320">
</p>

embargo keeps secrets and personal data out of what a Go program writes: logs, error reports, HTTP access logs and traces. It works inside the application, where the value is written, and the root module has no dependencies outside the standard library. The [`embargo` command](#command-line) masks the output of any program.

It exists for four jobs:

| You need to | embargo provides |
|---|---|
| Keep a known secret, such as an API key, from ever printing | [`Secret`](#values-that-must-never-print), which prints `[REDACTED]` through fmt, JSON, XML, templates and loggers |
| Log the structs, errors and JSON you already have | [A slog handler and `MaskJSON`](#mask-structs-without-changing-their-types) that keep keys, types and nesting, plus [adapters](#loggers-and-services) for other loggers and SDKs |
| Catch secrets nobody declared, such as a card number inside an error message | [39 built-in detectors](#find-and-mask-sensitive-text) that check the values: tokens, URL passwords, cards, bank numbers, email, IPs, phone numbers |
| Prove in CI that no secret reaches the output | [`embargotest`](#fail-tests-on-leaks), which fails a test when a fake secret appears in stdout, logs, HTTP responses or child processes |

Redaction in a log pipeline can still run after it; embargo stops the leak where it is written. See [what it misses](doc/cases.md), its [accuracy](#accuracy) and [speed](#benchmarks).

## Quick start

Requires Go 1.26.11 or later.

```sh
go get github.com/nao1215/embargo@v0.19.0
```

<!-- example: example_test.go:ExampleNewSlogHandler_quickStart -->
```go
// next is the handler you already use, such as slog.NewJSONHandler(os.Stdout, nil).
logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner()))

logger.Info("login failed", "email", "alice@example.com", "password", "hunter2", "request_id", "req-7f3a")

// Output: {"level":"INFO","msg":"login failed","email":"[REDACTED]","password":"[REDACTED]","request_id":"req-7f3a"}
```

Wrap `next` before calling `With` on it: attributes bound to `next` itself are written unmasked. IP addresses are masked by default; [access logs](#loggers-and-services) show how to keep the client address.

## Values that must never print

<!-- example: example_test.go:ExampleNewSecret -->
```go
key := embargo.NewSecret("fake-key")

fmt.Println(key)

// Output: [REDACTED]
```

`key.Reveal()` returns the value; `Input` decodes one from JSON, config files and SQL rows. [Secret, Input and your own types](doc/values.md)

## Mask structs without changing their types

<!-- example: example_test.go:ExampleNewSlogHandler_struct -->
```go
// An existing type: no tags, no embargo field types.
type User struct {
	Name     string
	Email    string
	Password string
}
logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner()))

logger.Info("signup", "user", User{Name: "carol", Email: "carol@example.com", Password: "hunter2"})

// Output: {"level":"INFO","msg":"signup","user":{"Name":"carol","Email":"[REDACTED]","Password":"[REDACTED]"}}
```

<!-- example: example_test.go:ExampleScanner_MaskJSON -->
```go
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
// Sanitize an audit export before uploading it to a support system.
safe, err := scanner.MaskJSON([]byte(`{"user":{"email":"alice@example.com","password":"opaque"},"amount":125,"paid":true}`))
if err != nil {
	panic(err)
}
fmt.Println(string(safe))
// Output:
// {"user":{"email":"[REDACTED]","password":"[REDACTED]"},"amount":125,"paid":true}
```

Clean values keep their JSON types; a detected number becomes a marker string. [Key rules and structured values](doc/logging.md)

## Loggers and services

| Logger | Wrap it with |
|---|---|
| log/slog, any slog.Handler | `embargo.NewSlogHandler(next, scanner)` |
| go.uber.org/zap | [`embargozap.NewWriteSyncer(next, scanner)`](adapters/zap/example_test.go) |
| github.com/rs/zerolog | [`embargozerolog.NewWriter(next, scanner)`](adapters/zerolog/example_test.go) |
| github.com/sirupsen/logrus | [`embargologrus.NewFormatter(next, scanner)`](adapters/logrus/example_test.go) |
| net/http server access log | [`embargo.NewHTTPHandler(next, logger, scanner)`](example_test.go) |
| gRPC server, unary and stream | [`embargogrpc.NewUnaryServerInterceptor(logger, scanner)`](adapters/grpc/example_test.go) |
| OpenTelemetry SDK logs and spans | [`embargootel.NewLogExporter(next, scanner)`](adapters/otel/example_test.go) |
| Sentry events | [`embargosentry.NewBeforeSend(scanner)`](adapters/sentry/example_test.go) |
| log, fmt and anything else | `Secret` values, or `embargo.Mask` on the text before writing |

Access logs usually need the client address. Select kinds without `KindIPAddr`:

<!-- example: example_test.go:ExampleWithKinds_accessLog -->
```go
scanner := embargo.NewScanner(embargo.WithKinds(
	embargo.KindCredential, embargo.KindServiceToken, embargo.KindJWT, embargo.KindEmail, embargo.KindPAN,
))
line := `203.0.113.7 - - [17/Nov/2026:10:00:00 +0000] "GET /reset?email=alice@example.com&token=sk-proj-Fake0Fake0Fake0Fake0Fake0Fake0 HTTP/1.1" 302 0`
fmt.Println(embargo.Mask(line, scanner.ScanString(line)))
// Output: 203.0.113.7 - - [17/Nov/2026:10:00:00 +0000] "GET /reset?email=[REDACTED]&token=[REDACTED] HTTP/1.1" 302 0
```

The HTTP and gRPC hooks mask what they log, not the request or response. [Adapters](doc/adapters.md) · [Size limits and failure records](doc/logging.md#bounds-and-failures)

## Find and mask sensitive text

embargo has 39 built-in detectors (19 run by default). Formats used in only one country, such as My Number or US routing numbers, are opt-in: `WithMoreKinds` adds them to the default, and `WithAll` turns on everything.

<!-- example: example_test.go:ExampleKindCredential -->
```go
text := "postgres://reader:forgotten@db.example/orders"
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
// Output: postgres://reader:[REDACTED]@db.example/orders
```

| Group | Detectors | What is detected |
|---|---:|---|
| Credentials | 9 | URL and DSN passwords, `password=` and auth headers, AWS, GitHub, Slack, OpenAI and other tokens, JWT, PEM keys |
| Cards | 5 | Card numbers (Luhn), CVV, expiry, payment tokens; merchant IDs are opt-in |
| Bank | 6 | IBAN and bank account numbers; SWIFT/BIC, ABA routing, UK sort code and ACH trace are opt-in |
| Crypto | 2 | Bitcoin and Ethereum addresses |
| Personal | 6 | Email, IP address, international phone numbers; Japanese and North American phone numbers and My Number are opt-in |
| National IDs | 11 | Opt-in US, UK, Indian, Brazilian, Chinese, Korean and Canadian identifiers; [rules and measured limits](doc/countries.md) |

<details>
<summary>All 39 kinds, their Examples and defaults</summary>


<!-- detectors:start -->
| Kind | Input and output | Default |
|---|---|---|
| [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindServiceToken) | on |
| [KindHighEntropy](https://pkg.go.dev/github.com/nao1215/embargo@main#KindHighEntropy) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindHighEntropy) | off |
| [KindCredential](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCredential) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindCredential) | on |
| [KindPAN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPAN) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindPAN) | on |
| [KindEmail](https://pkg.go.dev/github.com/nao1215/embargo@main#KindEmail) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindEmail) | on |
| [KindJPPhone](https://pkg.go.dev/github.com/nao1215/embargo@main#KindJPPhone) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindJPPhone) | off |
| [KindUSPhone](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSPhone) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindUSPhone) | off |
| [KindPhone](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPhone) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindPhone) | on |
| [KindMyNumber](https://pkg.go.dev/github.com/nao1215/embargo@main#KindMyNumber) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindMyNumber) | off |
| [KindJWT](https://pkg.go.dev/github.com/nao1215/embargo@main#KindJWT) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindJWT) | on |
| [KindAWSKey](https://pkg.go.dev/github.com/nao1215/embargo@main#KindAWSKey) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindAWSKey) | on |
| [KindIBAN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindIBAN) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindIBAN) | on |
| [KindIPAddr](https://pkg.go.dev/github.com/nao1215/embargo@main#KindIPAddr) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindIPAddr) | on |
| [KindSWIFTBIC](https://pkg.go.dev/github.com/nao1215/embargo@main#KindSWIFTBIC) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindSWIFTBIC) | off |
| [KindABARouting](https://pkg.go.dev/github.com/nao1215/embargo@main#KindABARouting) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindABARouting) | off |
| [KindUKSortCode](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUKSortCode) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindUKSortCode) | off |
| [KindCVV](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCVV) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindCVV) | on |
| [KindCardExpiry](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCardExpiry) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindCardExpiry) | on |
| [KindPaymentToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPaymentToken) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindPaymentToken) | on |
| [KindBankAccount](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBankAccount) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindBankAccount) | on |
| [KindACHTrace](https://pkg.go.dev/github.com/nao1215/embargo@main#KindACHTrace) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindACHTrace) | off |
| [KindMerchantID](https://pkg.go.dev/github.com/nao1215/embargo@main#KindMerchantID) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindMerchantID) | off |
| [KindBTC](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBTC) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindBTC) | on |
| [KindETH](https://pkg.go.dev/github.com/nao1215/embargo@main#KindETH) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindETH) | on |
| [KindGitHubToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindGitHubToken) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindGitHubToken) | on |
| [KindSlackToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindSlackToken) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindSlackToken) | on |
| [KindGoogleAPIKey](https://pkg.go.dev/github.com/nao1215/embargo@main#KindGoogleAPIKey) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindGoogleAPIKey) | on |
| [KindPrivateKeyPEM](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPrivateKeyPEM) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindPrivateKeyPEM) | on |
| [KindUSSSN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSSSN) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindUSSSN) | off |
| [KindUSITIN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSITIN) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindUSITIN) | off |
| [KindUKNINO](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUKNINO) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindUKNINO) | off |
| [KindUKNHS](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUKNHS) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindUKNHS) | off |
| [KindIndiaAadhaar](https://pkg.go.dev/github.com/nao1215/embargo@main#KindIndiaAadhaar) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindIndiaAadhaar) | off |
| [KindIndiaPAN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindIndiaPAN) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindIndiaPAN) | off |
| [KindBrazilCPF](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBrazilCPF) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindBrazilCPF) | off |
| [KindBrazilCNPJ](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBrazilCNPJ) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindBrazilCNPJ) | off |
| [KindChinaResidentID](https://pkg.go.dev/github.com/nao1215/embargo@main#KindChinaResidentID) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindChinaResidentID) | off |
| [KindKoreaRRN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindKoreaRRN) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindKoreaRRN) | off |
| [KindCanadaSIN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCanadaSIN) | [Example](https://pkg.go.dev/github.com/nao1215/embargo@main#example-KindCanadaSIN) | off |
<!-- detectors:end -->

</details>

[Every detector and how it validates](doc/detectors.md) · [Provider token formats](doc/credentials.md)

<!-- masking:start -->
| Operation | Actual text |
|---|---|
| Input | `INFO checkout email=alice@example.com card=4111111111111111` |
| [Mask](example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]` |
| [MaskFunc: keep last four](example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]1111` |
| [Overlapping matches](example_test.go) | `token=abcdef` with `abcd cdef` → `token=[REDACTED]` |
<!-- masking:end -->

`WithMaskFunc` applies the same replacement to log records, MaskJSON and the adapters. [Scanner options and custom replacements](doc/masking.md)

<!-- narrowing-line:start -->
Pick the kinds you need: on 2.7 KB of log lines with no secret, `WithKinds(KindEmail)` returns in 0.10 µs because there is no `@` to inspect, while `WithAll()` takes 65 µs. [Per-detector benchmarks](doc/benchmarks.md)
<!-- narrowing-line:end -->

## Fail tests on leaks

Add one line to a package's tests:

`func TestMain(m *testing.M) { os.Exit(embargotest.Guard(m)) }`

Guard reruns the package tests and fails when a fake secret, in any common encoding, or a detected value appears in stdout, stderr, default slog output or child processes. [ExampleGuard](embargotest/example_test.go)

For one test, a recorder checks that the expected output exists and the canary did not escape:

<!-- test: doc_test.go:TestReadmeCheckOutput -->
```go
func TestReadmeCheckOutput(t *testing.T) {
    t.Parallel()
    recorder := embargotest.New(t)
    next := slog.NewJSONHandler(recorder.Writer("logs"), nil)
    // Wrap next first; attributes bound with next.WithAttrs would skip embargo.
    logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner())).With("api_token", string(recorder.Canary()))

    logger.Info("accepted", "email", "alice@example.com")

    recorder.ExpectJSON("logs", nil, map[string]string{"msg": "accepted", "email": "[REDACTED]"}, 1)
    recorder.Check()
}
```

[Keep your masking, add the leak test](doc/keep-your-masking.md) · [HTTP, child processes and canaries](doc/testing-output.md)

## Command line

The `embargo` command reads lines and writes them masked, with no network access.

```sh
go install github.com/nao1215/embargo/cmd/embargo@v0.19.0
```

| Where | Command |
|---|---|
| An application that prints secrets | `embargo run ./app >> app.log` |
| Logs shared in an issue or a chat | `kubectl logs deploy/api \| embargo > share.log` |
| A live log before it is shipped | `tail -f app.log \| embargo \| your-shipper` |
| A CI gate on a saved log | `out=$(embargo --format jsonl app.log) && test -z "$out"` |

<!-- cli-example: e2e/atago/cli.atago.yaml -->
```text
$ printf '%s\n' 'login failed for alice@example.com from 203.0.113.7' | embargo
login failed for [REDACTED] from [REDACTED]
```

A JSON line keeps its keys, types and nesting. `--format json` prints per-kind counts and `--format jsonl` one line per finding; neither prints a matched value. [Flags, limits and CI use](doc/audit.md)

## Accuracy

[Per-detector precision and recall on a held-out synthetic set](doc/accuracy.md) · [Credential detectors](doc/credentials-accuracy.md)

<!-- real-logs-summary:start -->
15 public datasets, 239.9 MB, 1,048,835 lines of LogHub system logs plus web access, Kubernetes audit and CloudTrail logs. [Measured false positives](doc/real-logs.md) are sample estimates on previously seen splits, with no recall claim. [Licenses and classification rules](doc/accuracy.md#public-system-logs)
<!-- real-logs-summary:end -->

## Testing

<!-- techniques:start -->
| Technique | Bug class caught here |
|---|---|
| Examples and unit tests | [Wrong public outputs](doc/testing.md#examples-and-unit-tests) |
| Generated properties | [Missing checksum combinations](doc/testing.md#generated-properties) |
| Metamorphic relations | [Inconsistent transformed findings](doc/testing.md#metamorphic-relations) |
| Quint and model replay | [Invalid lifecycle transitions](doc/testing.md#quint-and-model-replay) |
| Lean reference proofs | [Checksum and offset-map errors](doc/testing.md#lean-reference-proofs) |
| Intentional snapshots | [Changed output structure](doc/testing.md#intentional-snapshots) |
| Independent differential oracles | [Shared oracle mistakes](doc/testing.md#independent-differential-oracles) |
| Structure-aware fuzzing | [Malformed nested inputs](doc/testing.md#structure-aware-fuzzing) |
| Mutation testing | [Assertions missing changed logic](doc/testing.md#mutation-testing) |
| Real logger and SDK output | [Serializer and SDK leaks](doc/testing.md#real-logger-and-sdk-output) |
| Race and lifecycle tests | [Races and hanging pipes](doc/testing.md#race-and-lifecycle-tests) |
| Paired CI benchmarks | [Runner noise hiding regressions](doc/testing.md#paired-ci-benchmarks) |
| Prose and policy checks | [Stale docs and rules](doc/testing.md#prose-and-policy-checks) |
| Adversarial budgets | [Resource amplification and spoofing](doc/testing.md#adversarial-budgets) |
<!-- techniques:end -->

<!-- testing-metrics:start -->
Coverage 99.4% · mutation score 89.18% · 13 fuzz targets, 2208636 executions.
<!-- testing-metrics:end -->

[Commands, measurement scope and conditions](doc/testing.md). [Real output of each logger and SDK](tests/README.md#tested-outputs).

## Benchmarks

<!-- speed-summary:start -->
On the same five JSON slog events, embargo is 1.11 to 1.38 times faster than go-masker given the same email and card rules, and embargo's default scanner is 1.83 to 4.34 times faster than pii-shield's default policy. [Time per event](doc/comparison.md#time-and-allocations)
<!-- speed-summary:end -->

<!-- benchmarks:start -->
![Time per log event](doc/images/log-event-time.svg)

[Configurations, medians and allocations](doc/comparison.md) · [Full scanner benchmark plot](doc/benchmarks.md).
<!-- benchmarks:end -->

## Compared with other Go libraries

Each library logs the same service scenarios. A catch means the planted value was removed; partial masks count. go-masker v3 `Sensitive` ties `Secret` on fmt, JSON, XML and slog, and masq, go-masker and go-mask catch a tag-only value that embargo misses.

![Scenario catch rate](doc/images/scenario-catch.svg)

<!-- leak-scenarios:start -->
| Service output | embargo slog | embargo zap | pii-shield v3.0.0 | ferret-scan v2.4.3 | masq v0.2.3 | slog-formatter v1.3.0 | go-mask v0.6.2 | go-masker v0.6.1 | godlp v1.2.15 |
|---|---|---|---|---|---|---|---|---|---|
| Password under the key `password` | caught | caught | caught | caught | caught | caught | caught | caught | leaked |
| Config struct holding a database DSN | caught | caught | caught | leaked | caught | leaked | leaked | caught | leaked |
| DSN inside a wrapped error | caught | caught | caught | leaked | caught | leaked | leaked | caught | leaked |
| DSN and an API key joined with errors.Join | caught | caught | caught | leaked | leaked | leaked | leaked | caught | leaked |
| Bearer header value in a log message | caught | caught | caught | leaked | leaked | leaked | leaked | caught | leaked |
| Third-party API key in a log message | caught | caught | caught | leaked | leaked | leaked | leaked | leaked | leaked |
| Redirect URL query, never logged | leaked | leaked | leaked | leaked | leaked | leaked | leaked | leaked | leaked |
<!-- leak-scenarios:end -->

[Exact outputs, setup and speed](doc/comparison.md).

## Contributing

[Report a bug](https://github.com/nao1215/embargo/issues), or [add a synthetic regression](CONTRIBUTING.md) and open a pull request. You can also [sponsor maintenance](https://github.com/sponsors/nao1215).

## License

[MIT License](LICENSE).

The [Go gopher](https://go.dev/blog/gopher) was designed by [Renee French](https://reneefrench.blogspot.com/) and is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Artwork details and license terms are in [image attribution](doc/images/ATTRIBUTION.md).

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
