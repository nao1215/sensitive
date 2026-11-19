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

embargo keeps secrets and personal data out of what a Go program writes: logs, error reports, HTTP access logs and traces. It works inside the application, where the value is written, and the root module has no dependencies outside the standard library.

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
go get github.com/nao1215/embargo@v0.17.0
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

`key.Reveal()` returns the value; `Input` decodes one from JSON, config files and SQL rows. [Secret, Input and your own types](doc/values.md) · [Compared with go-masker's Sensitive](doc/comparison.md#keeping-a-known-secret-out-typed-wrappers)

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

| Logger | Wrap it with | Module |
|---|---|---|
| log/slog: TextHandler, JSONHandler or any other slog.Handler | `embargo.NewSlogHandler(next, scanner)` | root, standard library only |
| go.uber.org/zap | [`embargozap.NewWriteSyncer(next, scanner)`](adapters/zap/example_test.go) | `adapters/zap` |
| github.com/rs/zerolog | [`embargozerolog.NewWriter(next, scanner)`](adapters/zerolog/example_test.go) | `adapters/zerolog` |
| github.com/sirupsen/logrus | [`embargologrus.NewFormatter(next, scanner)`](adapters/logrus/example_test.go) | `adapters/logrus` |
| net/http server access log | [`embargo.NewHTTPHandler(next, logger, scanner)`](example_test.go) | root, standard library only |
| gRPC server, unary and stream | [`embargogrpc.NewUnaryServerInterceptor(logger, scanner)`](adapters/grpc/example_test.go) | `adapters/grpc` |
| OpenTelemetry SDK logs and spans | [`embargootel.NewLogExporter(next, scanner)`](adapters/otel/example_test.go) | `adapters/otel` |
| Sentry events | [`embargosentry.NewBeforeSend(scanner)`](adapters/sentry/example_test.go) | `adapters/sentry` |
| log, fmt and anything else | `Secret` values, or `embargo.Mask` on the text before writing | root |

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

<!-- speed-summary:start -->
On the same five JSON slog events, embargo is 1.10 to 1.41 times faster than go-masker given the same email and card rules, and embargo's default scanner is 1.88 to 4.05 times faster than pii-shield's default policy. [Time per event](doc/comparison.md#time-and-allocations)
<!-- speed-summary:end -->

## Find and mask sensitive text

embargo has 39 built-in detectors (19 run by default). The default covers values that are secret or personal in every country, in formats every country uses. One country's formats, such as My Number or US routing numbers, are opt-in: `WithMoreKinds` adds them to the default, and `WithAll` turns on everything.

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

For one test, build the logger the way the service does; the recorder checks that the expected output exists and that the canary did not escape:

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

The `embargo` command masks a log file or a pipe line by line and keeps JSON lines' shape.

```sh
go install github.com/nao1215/embargo/cmd/embargo@v0.17.0
kubectl logs deploy/api | embargo
embargo --format jsonl app.log
```

<!-- cli-example: e2e/atago/cli.atago.yaml -->
```text
$ printf '%s\n' 'login failed for alice@example.com from 203.0.113.7' | embargo
login failed for [REDACTED] from [REDACTED]
```

`--format json` prints per-kind counts and `--format jsonl` one line per finding; neither prints a matched value. [Flags, limits and CI use](doc/audit.md)

## Tested outputs

Each link opens the test that produces and checks the shown output.

<!-- tested-outputs:start -->
| Output | Actual output (excerpt for SDKs) |
|---|---|
| [fmt](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L148-L148) | `embargo.Secret[string]([REDACTED])` |
| [slog TextHandler](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L149-L152) | `level=INFO msg=event token=[REDACTED] nested.again=[REDACTED]` |
| [slog JSONHandler](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L153-L156) | `{"level":"INFO","msg":"event","token":"[REDACTED]","nested":{"again":"[REDACTED]"}}` |
| [encoding/json](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L157-L157) | `"[REDACTED]"` |
| [encoding/xml](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L158-L163) | `<record><token>[REDACTED]</token></record>` |
| [text/template](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L164-L170) | `[REDACTED]` |
| [zap JSON core](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L171-L177) | `{"level":"info","msg":"event","token":"[REDACTED]"}` |
| [zerolog JSON](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L178-L182) | `{"level":"info","token":"[REDACTED]","message":"event"}` |
| [logrus JSON](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L183-L189) | `{"level":"info","msg":"event","token":"[REDACTED]"}` |
| [OTel SDK](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L988-L1076) | `{"Key":"key","Value":{"Type":"STRING","Value":"[REDACTED]"}}` |
| [Sentry](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L650-L735) | `"signing":{"key":"[REDACTED]"}` |
| [HTTP](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L230-L252) | `[REDACTED]` |
| [Child panic](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L254-L264) | `panic: [REDACTED]` |
<!-- tested-outputs:end -->

[Complete integration checks](tests/README.md).

## Accuracy

Held-out synthetic set, default minimum confidence 0. [Generation, test cases and observed misses](doc/accuracy.md) · [Credential detectors](doc/credentials-accuracy.md) · [Audit your own logs](doc/audit.md)

<!-- accuracy:start -->
[Per-detector precision, recall and charts](doc/accuracy.md).

| Detector details | | |
|---|---|---|
| [aba_routing](doc/accuracy.md#aba-routing) | [ach_trace](doc/accuracy.md#ach-trace) | [awskey](doc/accuracy.md#awskey) |
| [bank_account](doc/accuracy.md#bank-account) | [btc](doc/accuracy.md#btc) | [card_expiry](doc/accuracy.md#card-expiry) |
| [cvv](doc/accuracy.md#cvv) | [email](doc/accuracy.md#email) | [eth](doc/accuracy.md#eth) |
| [github_token](doc/accuracy.md#github-token) | [google_api_key](doc/accuracy.md#google-api-key) | [iban](doc/accuracy.md#iban) |
| [ipaddr](doc/accuracy.md#ipaddr) | [jwt](doc/accuracy.md#jwt) | [merchant_id](doc/accuracy.md#merchant-id) |
| [mynumber](doc/accuracy.md#mynumber) | [pan](doc/accuracy.md#pan) | [payment_token](doc/accuracy.md#payment-token) |
| [phone](doc/accuracy.md#phone) | [phone_jp](doc/accuracy.md#phone-jp) | [phone_us](doc/accuracy.md#phone-us) |
| [private_key_pem](doc/accuracy.md#private-key-pem) | [slack_token](doc/accuracy.md#slack-token) | [swiftbic](doc/accuracy.md#swiftbic) |
| [uk_sortcode](doc/accuracy.md#uk-sortcode) | | |
<!-- accuracy:end -->

<!-- real-logs-summary:start -->
[Public-log chart and measured results](doc/real-logs.md).

15 public datasets, 239.9 MB, 1,048,835 lines: LogHub system logs plus web access, Kubernetes audit and CloudTrail logs. [Licenses, classification rules, per-kind and per-configuration FP/GB](doc/accuracy.md#public-system-logs). Rates are sample estimates on previously seen splits; contact and endpoint references count as sensitive data, and no recall claim is made.
<!-- real-logs-summary:end -->

## Testing

<!-- techniques:start -->
| Technique | Bug class caught here |
|---|---|
| Examples and unit tests | [Wrong public outputs](doc/testing.md#examples-and-unit-tests) |
| Generated properties | [Missing checksum combinations](doc/testing.md#generated-properties) |
| Metamorphic relations | [Inconsistent transformed findings](doc/testing.md#metamorphic-relations) |
| Quint and model replay | [Invalid lifecycle transitions](doc/testing.md#quint-and-model-replay) |
| Lean reference proofs | [Arithmetic and interval errors](doc/testing.md#lean-reference-proofs) |
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

[Commands, measurement scope and conditions](doc/testing.md).

## Benchmarks

<!-- benchmarks:start -->
![Time per log event](doc/images/log-event-time.svg)

The same event through slog alone, embargo with the email and card rules masq and go-masker are given, embargo's default scanner against pii-shield's default policy, masq and go-masker. [Configurations, medians and allocations](doc/comparison.md) · [Full scanner benchmark plot](doc/benchmarks.md).
<!-- benchmarks:end -->

<!-- narrowing-summary:start -->
Recorded scanner medians (ten interleaved samples):

| Selection | Clean ns/op | Dirty ns/op | Clean / dirty speedup over WithAll |
|---|---:|---:|---|
| all | 64,763 | 6,837,398 | 1.00× / 1.00× |
| kinds1 | 101 | 22,310 | 641.22× / 306.47× |
| kinds3 | 8,648 | 496,620 | 7.49× / 13.77× |
| kinds8 | 10,174 | 1,541,042 | 6.37× / 4.44× |

[kinds1/3/8 definitions, input sizes and uncertainty](doc/benchmarks.md#choose-the-kinds-the-application-needs). Narrower selection avoids irrelevant detections and gives up their recall.
<!-- narrowing-summary:end -->

## Compared with other Go libraries

The same scenarios, service probe and log events run against pii-shield, ferret-scan, masq, go-masker, slog-formatter, go-mask and godlp. A catch means the planted value was removed; partial masks count.

| Job | Strongest measured option | Where others win or tie |
|---|---|---|
| Keep a known secret from printing | embargo `Secret`, hidden on every tested path including unexported fields | [ggwhite/go-masker v3](https://github.com/ggwhite/go-masker) `Sensitive` ties on fmt, JSON, XML and slog ([table](doc/comparison.md#keeping-a-known-secret-out-typed-wrappers)) |
| Log existing structs and JSON with their shape | embargo: keys, groups and custom JSON output are scanned as structure | [pii-shield](https://github.com/pii-shield/pii-shield) and [ferret-scan](https://github.com/awslabs/ferret-scan) rewrite any logger's encoded line |
| Catch values nobody declared | embargo removes the most planted values below and, with pii-shield, every logged service leak | Tag-only values: [masq](https://github.com/m-mizutani/masq), [go-masker](https://github.com/icntswm/go-masker) and go-mask catch the one embargo misses |
| Prove in CI that nothing leaked | embargo `embargotest`, with canaries in logs, responses and child processes | None of the measured libraries; embargotest [works with any of them](doc/keep-your-masking.md) |

![Scenario catch rate](doc/images/scenario-catch.svg)

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

[Report a bug](https://github.com/nao1215/embargo/issues) → [add a synthetic regression](CONTRIBUTING.md) → open a pull request. You can also [sponsor maintenance](https://github.com/sponsors/nao1215).

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
