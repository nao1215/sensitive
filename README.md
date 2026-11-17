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
| Catch secrets nobody declared, such as a card number inside an error message | [38 built-in detectors](#find-and-mask-sensitive-text) that check the values: tokens, URL passwords, cards, bank numbers, email, IPs |
| Prove in CI that no secret reaches the output | [`embargotest`](#fail-tests-on-leaks), which fails a test when a fake secret appears in stdout, logs, HTTP responses or child processes |

Redaction in a log pipeline can still run after it; embargo stops the leak where it is written. See [what it misses](doc/cases.md), its [accuracy](#accuracy) and [speed](#benchmarks).

## Quick start

Requires Go 1.26.11 or later.

```sh
go get github.com/nao1215/embargo@v0.10.0
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

## Values that must never print

Wrap the value once; every formatter then sees the marker.

<!-- example: example_test.go:ExampleNewSecret -->
```go
key := embargo.NewSecret("fake-key")

fmt.Println(key)

// Output: [REDACTED]
```

`key.Reveal()` returns the value when the program really needs it. [Tested outputs](#tested-outputs) lists every path checked to print `[REDACTED]`, and `Input` loads such values from JSON, config files and SQL rows. [Secret, Input and your own types](doc/values.md)

Measured against the other typed wrapper, go-masker v3's `Sensitive`, on twelve standard output paths: both hide the value on fmt, JSON, XML, templates and slog, and only `Secret` stays hidden when it sits in an unexported struct field printed with `%+v`. [Output-path table](doc/comparison.md#keeping-a-known-secret-out-typed-wrappers)

## Mask structs without changing their types

Log the struct you already have. The handler encodes it as `slog.JSONHandler` would, masks detected values, and hides whole values under keys such as `password`, `token` or `authorization`.

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

`next` is the handler your logger already uses. The same rules apply to JSON that never reaches a logger, such as an API response or an audit export:

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

Numbers and booleans keep their types. `WithSensitiveKeys` replaces the key list. [Structured values and key rules](doc/logging.md)

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

<!-- example: example_test.go:ExampleNewSlogHandler_short -->
```go
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
logger := slog.New(embargo.NewSlogHandler(next, scanner))

logger.Info("checkout", "email", "alice@example.com")

// Output: {"level":"INFO","msg":"checkout","email":"[REDACTED]"}
```

Limits: MaskJSON bounds encoded input/output to 1 MiB, nesting to 64 and cumulative detector input to 4 MiB; logger writers include the newline in their 1 MiB limit. Recorder WithLimits bounds retained bytes and child Run time. Input decoding has no size limit; bound its upstream reader. MarshalJSON, LogValue, String and Error run before these byte limits apply, so their time and memory are not bounded; use Secret or a LogValuer returning a bounded value. [Details](doc/logging.md#bounds-and-failures)

Every adapter and hook uses the same detectors and key rules as the slog handler. The HTTP and gRPC hooks mask what they log, not the request your service receives or the response it sends. gin, echo and Connect servers are `http.Handler`s, so `NewHTTPHandler` wraps them unchanged; [a test runs all three](tests/integrations_test.go). [Installation and limits](doc/adapters.md)

Access logs usually need the client address. Select kinds without `KindIPAddress` to keep it while tokens and addresses in the request line are still masked:

<!-- example: example_test.go:ExampleWithKinds_accessLog -->
```go
scanner := embargo.NewScanner(embargo.WithKinds(
	embargo.KindCredential, embargo.KindServiceToken, embargo.KindJWT, embargo.KindEmail, embargo.KindPAN,
))
line := `203.0.113.7 - - [17/Nov/2026:10:00:00 +0000] "GET /reset?email=alice@example.com&token=sk-proj-Fake0Fake0Fake0Fake0Fake0Fake0 HTTP/1.1" 302 0`
fmt.Println(embargo.Mask(line, scanner.ScanString(line)))
// Output: 203.0.113.7 - - [17/Nov/2026:10:00:00 +0000] "GET /reset?email=[REDACTED]&token=[REDACTED] HTTP/1.1" 302 0
```

<!-- speed-summary:start -->
On the same five JSON slog events, go-masker takes 1.03 to 1.32 times and pii-shield 2.2 to 4.9 times embargo's time per event. [Time per event](doc/comparison.md#time-and-allocations)
<!-- speed-summary:end -->

## Find and mask sensitive text

embargo has 38 built-in detectors (26 run by default). `NewScanner()` runs the first five groups below except the entropy heuristic. The national IDs and the heuristic are opt-in: name them in `WithKinds`, or turn on everything with `WithAll`. The scanner reads the text itself, so no field has to be listed first.

<!-- example: example_test.go:ExampleKindCredential -->
```go
text := "postgres://reader:forgotten@db.example/orders"
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
// Output: postgres://reader:[REDACTED]@db.example/orders
```

| Group | Detectors | What is detected |
|---|---:|---|
| Credentials | 9 | URL and DSN passwords, `password=` and auth headers, tokens from AWS, GitHub, Slack, OpenAI and others, JWT, PEM keys |
| Cards | 5 | Card numbers (Luhn), CVV, expiry, payment tokens, merchant ID |
| Bank | 6 | IBAN, SWIFT/BIC, ABA routing, UK sort code, bank account, ACH trace |
| Crypto | 2 | Bitcoin and Ethereum addresses |
| Personal | 5 | Email, IP address, US and Japanese phone numbers, and My Number, including full-width digits |
| National IDs | 11 | Opt-in US, UK, Indian, Brazilian, Chinese, Korean and Canadian identifiers; [rules and measured limits](doc/countries.md) |

<details>
<summary>Matching rules and validation for all 38 kinds</summary>

The cells excerpt each constant's godoc; follow the Kind link for the full rule and confidence tiers. Default refers to `NewScanner()` without options.

<!-- detectors:start -->
| Kind | What it matches | How it is checked | Default |
|---|---|---|---|
| [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) | covers provider-prefixed secrets and Slack webhook credential paths | prefix and body checks yield 0.95 without a keyword or remote authentication | on |
| [KindHighEntropy](https://pkg.go.dev/github.com/nao1215/embargo@main#KindHighEntropy) | looks for unlabeled runs of 32–256 ASCII letters, digits, _, - or + | Shannon entropy of at least 4.5 bits per byte and three of lowercase, uppercase, digit and symbol classes yield 0.3 | off |
| [KindCredential](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCredential) | locates nonempty assignment values, Authorization credentials and URL/DSN passwords | delimiter and quoting checks give 0.95, preserving labels, initial auth schemes, usernames and hosts | on |
| [KindPAN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPAN) | finds 13–19 digits with Visa, Mastercard, Amex, JCB, Discover, Diners or UnionPay prefixes | Luhn plus issuer length scores 1.0, a failed checksum 0.6, and an attached business label 0.4 | on |
| [KindEmail](https://pkg.go.dev/github.com/nao1215/embargo@main#KindEmail) | extracts ASCII local parts using letters, digits and .+-_ before @ and dotted domains using letters, digits and .- | structure checks score 0.7 or 0.8 for an unknown TLD and 0.9 or 1.0 for a known TLD | on |
| [KindJPPhone](https://pkg.go.dev/github.com/nao1215/embargo@main#KindJPPhone) | recognizes 10- or 11-digit Japanese numbers beginning with 0, allowing spaces, hyphens and parentheses | prefix/length checks score landlines 0.8, other accepted types 0.9, and business labels 0.4 | on |
| [KindUSPhone](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSPhone) | recognizes separated ten-digit North American numbers such as (202) 555-0123, 202-555-0123, 202.555.0123 or 202 555 … | area and exchange codes are checked against the numbering plan (area 2–9 then 0–8, exchange 2–9 and not N11) and the … | on |
| [KindMyNumber](https://pkg.go.dev/github.com/nao1215/embargo@main#KindMyNumber) | recognizes 12 digits with optional spaces or hyphens as Japanese individual-number candidates | the weighted MOD 11 check gives 0.95, or 0.4 under a business label, without requiring a keyword; only a contiguous … | on |
| [KindJWT](https://pkg.go.dev/github.com/nao1215/embargo@main#KindJWT) | parses eyJ-prefixed base64url text with exactly two dots and nonempty header and payload segments | header checks yield 0.5, 0.7 or 0.8 with an empty signature, and 0.7, 0.9 or 1.0 otherwise | on |
| [KindAWSKey](https://pkg.go.dev/github.com/nao1215/embargo@main#KindAWSKey) | identifies AKIA or ASIA followed by exactly 16 uppercase ASCII letters or digits (20 characters total) | length, alphabet and alphanumeric boundary checks give 0.95 without a context keyword or authentication | on |
| [KindIBAN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindIBAN) | accepts two ASCII country letters, two digits and an alphanumeric BBAN with optional internal spaces | country length and MOD 97 checks give 0.95, rejecting check digits 00, 01 and 99 without requiring a keyword | on |
| [KindIPAddr](https://pkg.go.dev/github.com/nao1215/embargo@main#KindIPAddr) | extracts dotted IPv4 decimal octets and colon-separated IPv6 hexadecimal text, including :: shorthand | net.ParseIP validation gives 0.8, excluding unspecified and loopback addresses with no keyword needed | on |
| [KindSWIFTBIC](https://pkg.go.dev/github.com/nao1215/embargo@main#KindSWIFTBIC) | accepts 8 or 11 ASCII alphanumerics as four bank letters, two country letters, location and optional branch | country and structure checks give 0.85, with case ignored and no institution lookup | on |
| [KindABARouting](https://pkg.go.dev/github.com/nao1215/embargo@main#KindABARouting) | selects 9 consecutive digits beginning 01–12, 21–32, 61–72 or 80 as US routing candidates | the repeating 3,7,1 weighted MOD 10 checksum must pass, giving 0.85 without a keyword | on |
| [KindUKSortCode](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUKSortCode) | picks six digits in three pairs separated consistently by hyphens or spaces with matching separators, excluding … | structure checks give 0.7, or 0.55 for contextual date-like candidates, without a checksum | on |
| [KindCVV](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCVV) | finds 3 or 4 consecutive digits within 30 bytes of a verification-code keyword end | length and non-overlap checks yield 0.85 without a checksum | on |
| [KindCardExpiry](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCardExpiry) | reads MM/YY, MM/YYYY, MM-YY or MM-YYYY near expiration labels | month 01–12 and adjacent-digit checks yield 0.85, without checking whether the date is in the future | on |
| [KindPaymentToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPaymentToken) | covers Stripe identifiers and keys, PayPal PAYID- and Square sq0idp-/sq0csp- tokens | prefix and minimum-body checks yield 0.9 with no keyword or authentication | on |
| [KindBankAccount](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBankAccount) | looks for 4–17 consecutive digits within 50 bytes of a banking keyword end | length checks give 0.5, raised to 0.65 by nearby holder context, without a checksum | on |
| [KindACHTrace](https://pkg.go.dev/github.com/nao1215/embargo@main#KindACHTrace) | takes 15 consecutive digits within 50 bytes of an ACH or trace keyword end | prefix validation requires 01–12, 21–32, 61–72 or 80 and scores 0.75 without a checksum | on |
| [KindMerchantID](https://pkg.go.dev/github.com/nao1215/embargo@main#KindMerchantID) | finds 15 ASCII alphanumerics for merchant IDs or 8 consecutive digits at alphanumeric boundaries for terminal IDs | length and keyword-overlap checks give 0.7 without checksum validation | on |
| [KindBTC](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBTC) | recognizes mainnet 1/3 Base58 text of 25–34 characters or single-case bc1 text of 42 or 62 characters | Base58Check or Bech32/Bech32m checksum validation gives 0.95 without a keyword | on |
| [KindETH](https://pkg.go.dev/github.com/nao1215/embargo@main#KindETH) | captures 0x or 0X followed by exactly 40 hexadecimal characters at identifier boundaries | uniform-case hex scores 0.8 without checksum validation, while mixed case must pass EIP-55 (Keccak-256) for 0.95 … | on |
| [KindGitHubToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindGitHubToken) | distinguishes classic ghp_/gho_/ghu_/ghs_/ghr_ tokens from github_pat_ tokens | body-length and token-boundary checks yield 0.95 without a keyword or authentication | on |
| [KindSlackToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindSlackToken) | recognizes xoxb-, xoxp-, xoxa-, xoxo-, xoxr- and xoxs- followed by ASCII letters, digits or hyphens | a body of at least 10 characters and token-boundary checks yield 0.9, with no context keyword or authentication | on |
| [KindGoogleAPIKey](https://pkg.go.dev/github.com/nao1215/embargo@main#KindGoogleAPIKey) | looks for AIza followed by exactly 35 ASCII letters, digits, hyphens or underscores | the 39-character length and token-boundary checks give 0.9 without a keyword or authentication | on |
| [KindPrivateKeyPEM](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPrivateKeyPEM) | covers -----BEGIN headers whose same-line content ends in PRIVATE KEY or equals PGP PRIVATE KEY BLOCK, closed by five … | header grammar alone gives 0.99 without a keyword or key-material validation | on |
| [KindUSSSN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSSSN) | recognizes 9 digits, either contiguous or grouped 3-2-4 with hyphens | field checks yield 0.6, or 0.4 under a business label, with no keyword or checksum required | off |
| [KindUSITIN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSITIN) | finds 9 digits starting with 9, optionally hyphenated 3-2-4 | middle-group validation gives 0.6, or 0.4 under a business label, without a keyword or checksum | off |
| [KindUKNINO](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUKNINO) | accepts two uppercase ASCII letters, six digits and a suffix A–D, optionally spaced into groups of 2 letters, 2/2/2 … | prefix checks score 0.7, reduced to 0.4 by a business label, without requiring context or a checksum | off |
| [KindUKNHS](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUKNHS) | collects 10 digits, contiguous or spaced 3-3-4 | weighted MOD 11 validation yields 0.95, or 0.4 with a business label, and needs no keyword | off |
| [KindIndiaAadhaar](https://pkg.go.dev/github.com/nao1215/embargo@main#KindIndiaAadhaar) | accepts 12 digits beginning 2–9, contiguous or spaced 4-4-4 | Verhoeff checksum validation gives 0.95, lowered to 0.4 by business context, without a keyword | off |
| [KindIndiaPAN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindIndiaPAN) | recognizes five uppercase ASCII letters, four digits and one final uppercase letter | holder-type and nonzero-serial checks score 0.7, or 0.4 under a business label, with no keyword or checksum | off |
| [KindBrazilCPF](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBrazilCPF) | takes 11 digits, contiguous or formatted DDD.DDD.DDD-DD | both MOD 11 check digits must pass for 0.95, or 0.4 under a business label, without a keyword | off |
| [KindBrazilCNPJ](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBrazilCNPJ) | admits 12 uppercase ASCII alphanumerics and two digits, contiguous or formatted CC.CCC.CCC/CCCC-DD | two MOD 11 checks give 0.95, or 0.4 with a business label, without requiring a keyword | off |
| [KindChinaResidentID](https://pkg.go.dev/github.com/nao1215/embargo@main#KindChinaResidentID) | requires 17 digits followed by a digit or uppercase X, including a YYYYMMDD birth date | province, date, sequence and MOD 11-2 checks yield 0.95, or 0.4 under a business label, with no keyword | off |
| [KindKoreaRRN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindKoreaRRN) | reads 13 digits, contiguous or hyphenated 6-7, with a birth date and century/sex digit | the legacy weighted MOD 11 check scores 0.95, labeled check failures 0.6, and business labels 0.4 | off |
| [KindCanadaSIN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCanadaSIN) | finds 9 digits starting with 1–7 or 9, contiguous or hyphenated 3-3-3 | Luhn checksum validation yields 0.95, or 0.4 under a business label, without a keyword | off |
<!-- detectors:end -->

</details>

[Every detector and how it validates](doc/detectors.md) · [Provider token formats](doc/credentials.md)

Mask everything a scanner finds, or keep part of a value:

<!-- masking:start -->
| Operation | Actual text |
|---|---|
| Input | `INFO checkout email=alice@example.com card=4111111111111111` |
| [Mask](example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]` |
| [MaskFunc: keep last four](example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]1111` |
| [Overlapping matches](example_test.go) | `token=abcdef` with `abcd cdef` → `token=[REDACTED]` |
<!-- masking:end -->

`Scanner.ScanLines` reads files and streams line by line. [Scanner options and custom replacements](doc/masking.md)

<!-- narrowing-line:start -->
Pick the kinds you need: on 2.7 KB of log lines with no secret, `WithKinds(KindEmail)` returns in 0.10 µs because there is no `@` to inspect, while `WithAll()` takes 65 µs. [Per-detector benchmarks](doc/benchmarks.md)
<!-- narrowing-line:end -->

## Fail tests on leaks

Add one line to a package's tests:

`func TestMain(m *testing.M) { os.Exit(embargotest.Guard(m)) }`

Guard reruns the package tests and fails when a canary (a fake secret) or a detected value appears in stdout, stderr, default slog output or child processes. The canary is matched as raw bytes, hex, standard or URL-safe base64 at any byte alignment, and standard Go/JSON-escaped forms, so that check does not depend on the detectors. MIME-wrapped base64 and full Unicode escaping require decoding before recording. [ExampleGuard](embargotest/example_test.go)

For one test, a recorder checks both that the expected output exists and that no canary escaped:

<!-- test: doc_test.go:TestReadmeCheckOutput -->
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

[Keep your masking, add the leak test](doc/keep-your-masking.md) shows how to add only embargotest to existing masking. [HTTP, child processes, and canaries in env, files and headers](doc/testing-output.md)

In a sample service with planted leaks (a DSN, wrapped errors, an Authorization header, a token in a request body), the slog and zap paths masked every leak that reached a logger. The redirect URL never reaches a logger; `embargotest.HTTP` catches it. [Scenario table](doc/comparison.md#service-leak-scenarios)

## Command line

The `embargo` command masks log files or a pipe line by line, keeps JSON lines' shape and depends only on the standard library.

```sh
go install github.com/nao1215/embargo/cmd/embargo@v0.11.0
kubectl logs deploy/api | embargo
embargo --report --kinds all app.log
```

<!-- cli-example: e2e/atago/cli.atago.yaml -->
```text
$ printf '%s\n' 'login failed for alice@example.com from 203.0.113.7' | embargo
login failed for [REDACTED] from [REDACTED]
```

`--report` prints per-kind counts and masked byte locations instead, without echoing the input. [Flags, limits and comparing settings](doc/audit.md)

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
| [OTel SDK](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L980-L1068) | `{"Key":"key","Value":{"Type":"STRING","Value":"[REDACTED]"}}` |
| [Sentry](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L650-L733) | `"signing":{"key":"[REDACTED]"}` |
| [HTTP](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L230-L252) | `[REDACTED]` |
| [Child panic](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L254-L264) | `panic: [REDACTED]` |
<!-- tested-outputs:end -->

[Complete integration checks](tests/README.md).

## Accuracy

[Audit your own logs](doc/audit.md): count findings by Kind, inspect masked offsets and test settings that preserve diagnostic IDs.

Held-out synthetic set, default minimum confidence 0. [Generation, test cases and observed misses](doc/accuracy.md) · [Credential detectors](doc/credentials-accuracy.md), measured separately

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
| [phone_jp](doc/accuracy.md#phone-jp) | [phone_us](doc/accuracy.md#phone-us) | [private_key_pem](doc/accuracy.md#private-key-pem) |
| [slack_token](doc/accuracy.md#slack-token) | [swiftbic](doc/accuracy.md#swiftbic) | [uk_sortcode](doc/accuracy.md#uk-sortcode) |
<!-- accuracy:end -->

<!-- real-logs-summary:start -->
[Public-log chart and measured results](doc/real-logs.md).

8 public datasets, 92.4 MB, 819,576 lines. [Licenses, classification rules, per-kind and per-configuration FP/GB](doc/accuracy.md#public-system-logs). Rates are sample estimates on previously seen splits; contact and endpoint references count as sensitive data, and no recall claim is made.
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

The same event through slog alone, embargo, masq and go-masker. [Configurations, medians and allocations](doc/comparison.md) · [Full scanner benchmark plot](doc/benchmarks.md).
<!-- benchmarks:end -->

<!-- narrowing-summary:start -->
Recorded scanner medians (ten interleaved samples):

| Selection | Clean ns/op | Dirty ns/op | Clean / dirty speedup over WithAll |
|---|---:|---:|---|
| all | 64,763.000 | 6,837,398.5 | 1.00× / 1.00× |
| kinds1 | 101.000 | 22,310.0 | 641.22× / 306.47× |
| kinds3 | 8,648.500 | 496,620.0 | 7.49× / 13.77× |
| kinds8 | 10,173.500 | 1,541,041.5 | 6.37× / 4.44× |

[kinds1/3/8 definitions, input sizes and uncertainty](doc/benchmarks.md#choose-the-kinds-the-application-needs). Narrower selection avoids irrelevant detections and gives up their recall.
<!-- narrowing-summary:end -->

[Machine, method, profiles and full results](doc/benchmarks.md).

## Compared with other Go libraries

The same scenarios, service probe and log events run against pii-shield, ferret-scan, masq, go-masker, slog-formatter, go-mask and godlp, and the typed-wrapper paths against ggwhite/go-masker v3. A catch means the original planted value was removed; partial masks count. These configured examples are not a production accuracy estimate.

| Job | Strongest measured option | Where others win or tie |
|---|---|---|
| Keep a known secret from printing | embargo `Secret`, hidden on every tested path including unexported fields | [ggwhite/go-masker v3](https://github.com/ggwhite/go-masker) `Sensitive` ties on fmt, JSON, XML and slog ([table](doc/comparison.md#keeping-a-known-secret-out-typed-wrappers)) |
| Log existing structs and JSON with their shape | embargo: keys, groups and custom JSON output are scanned as structure | [pii-shield](https://github.com/pii-shield/pii-shield) and [ferret-scan](https://github.com/awslabs/ferret-scan) rewrite any logger's encoded line |
| Catch values nobody declared | embargo removes the most planted values below and, with pii-shield, every logged service leak | Tag-only values: [masq](https://github.com/m-mizutani/masq), [go-masker](https://github.com/icntswm/go-masker) and go-mask catch the one embargo misses |
| Prove in CI that nothing leaked | embargo `embargotest`, with canaries in logs, responses and child processes | None of the measured libraries; embargotest [works with any of them](doc/keep-your-masking.md) |

![Scenario catch rate](doc/images/scenario-catch.svg)

pii-shield also runs as a Kubernetes sidecar outside the process, and ferret-scan scans documents and images; embargo stays inside the Go process where the value is written. Its default scanner masks the invalid-Luhn control too, a false positive masq shares. [Exact outputs, setup, runtime dependencies and speed](doc/comparison.md) document the strengths and limits of every configuration.

The service probe below also checks a redirect that bypasses every logger. `embargotest.HTTP` catches that response leak:

<!-- leak-scenarios:start -->
| Service output | embargo slog | embargo zap | pii-shield v3.0.0 | ferret-scan v1.10.0 | masq v0.2.3 | slog-formatter v1.3.0 | go-mask v0.6.2 | go-masker v0.6.1 | godlp v1.2.15 |
|---|---|---|---|---|---|---|---|---|---|
| Password under the key `password` | caught | caught | caught | caught | caught | caught | caught | caught | leaked |
| Config struct holding a database DSN | caught | caught | caught | leaked | caught | leaked | leaked | caught | leaked |
| DSN inside a wrapped error | caught | caught | caught | leaked | caught | leaked | leaked | caught | leaked |
| DSN and an API key joined with errors.Join | caught | caught | caught | leaked | leaked | leaked | leaked | caught | leaked |
| Bearer header value in a log message | caught | caught | caught | leaked | leaked | leaked | leaked | caught | leaked |
| Third-party API key in a log message | caught | caught | caught | leaked | leaked | leaked | leaked | leaked | leaked |
| Redirect URL query, never logged | leaked | leaked | leaked | leaked | leaked | leaked | leaked | leaked | leaked |
<!-- leak-scenarios:end -->

[Service setup and full results](doc/comparison.md#service-leak-scenarios).

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
