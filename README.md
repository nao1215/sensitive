# embargo

embargo detects and masks personal data, payment data and secrets in text, logs and test output: a cross-platform Go library with zero dependencies.

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg?style=flat-square)](#contributors)
<!-- ALL-CONTRIBUTORS-BADGE:END -->
[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/embargo.svg)](https://pkg.go.dev/github.com/nao1215/embargo)
[![MultiPlatformUnitTest](https://github.com/nao1215/embargo/actions/workflows/unit_test.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/unit_test.yml)
[![reviewdog](https://github.com/nao1215/embargo/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/reviewdog.yml)
[![govulncheck](https://github.com/nao1215/embargo/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/govulncheck.yml)
[![Coverage](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/embargo/coverage.svg)](https://github.com/nao1215/embargo/actions/workflows/coverage.yml)
[![OpenSSF Scorecard](https://github.com/nao1215/embargo/actions/workflows/scorecard.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/scorecard.yml)
[![License](https://img.shields.io/github/license/nao1215/embargo)](LICENSE)

<img src="doc/images/logo-small.png" alt="embargo" width="320">

- Mask card numbers and emails before logs leave your service.
- Check in tests that an HTTP handler or child process never writes a secret.
- Scan support messages and imported files for personal data.
- Detect Japanese phone numbers and My Number, including full-width digits.

## Quick start

These examples use the unreleased API on main (Go 1.26.11 or later).

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
	if _, err := fmt.Println(embargo.Mask(text, scanner.ScanString(text))); err != nil {
		panic(err)
	}
	// Output: email=[REDACTED] card=[REDACTED]
}
```

NewScanner() and WithAll() enable every built-in, including IP addresses and context-based detectors. Use WithKinds to narrow the selection. Findings retain all overlaps and contain byte offsets rather than raw values.

## Why embargo?

[Gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog) scan repositories and files for secrets; [Presidio](https://github.com/microsoft/presidio) provides detection and anonymization in Python. Secret-wrapper libraries hide values that callers explicitly wrap, but do not detect sensitive text.

embargo runs inside a Go program: its slog handler detects and masks log content at runtime, while Secret values print as [REDACTED]. In tests, embargotest checks actual output with canaries and the detectors, including HTTP responses and child processes; the [output tests](tests/compatibility_integration_test.go) exercise these paths.

## Supported detectors

| Kind | Detects | Validation |
|--------|---------|------------|
| `KindPAN` | Credit card numbers (Visa, Mastercard, Amex, JCB, Discover, Diners, UnionPay) | BIN prefix + Luhn algorithm |
| `KindEmail` | Email addresses | Structure + known TLD check |
| `KindJPPhone` | Japanese phone numbers (mobile, landline, IP phone, toll-free, M2M/IoT, service) | Prefix classification + digit count |
| `KindMyNumber` | Japanese My Number (12-digit individual number) | MOD 11 check digit |
| `KindJWT` | JSON Web Tokens | Header decode + `alg` key check |
| `KindAWSKey` | AWS Access Key IDs (`AKIA...` / `ASIA...`) | Prefix + 20-char alphanumeric |
| `KindIBAN` | International Bank Account Numbers | Country code + MOD 97 check digit |
| `KindIPAddr` | IPv4 and IPv6 addresses | `net.ParseIP` + octet range |
| `KindSWIFTBIC` | SWIFT/BIC codes | Format + country code validation |
| `KindABARouting` | US ABA routing numbers | Prefix range + checksum |
| `KindUKSortCode` | UK sort codes (XX-XX-XX) | Pattern + boundary checks |
| `KindCVV` | Card verification values (CVV/CVC/CID) | Context keyword + digit length (context-based, weaker) |
| `KindCardExpiry` | Card expiration dates | Context keyword + MM/YY validation (context-based, weaker) |
| `KindPaymentToken` | Payment processor tokens (Stripe/PayPal/Square) | Prefix + minimum body length |
| `KindBankAccount` | Bank account numbers (context-based) | Context keyword + digit range (context-based, weaker) |
| `KindACHTrace` | ACH trace numbers | Context keyword + prefix range (context-based, weaker) |
| `KindMerchantID` | Merchant/terminal IDs | Context keyword + format (context-based, weaker) |
| `KindBTC` | Bitcoin addresses (P2PKH, P2SH, Bech32, Bech32m/Taproot) | Base58Check (double SHA-256) / Bech32 polynomial checksum |
| `KindETH` | Ethereum addresses (0x + 40 hex) | EIP-55 mixed-case checksum (Keccak-256) |
| `KindGitHubToken` | GitHub tokens (classic `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, fine-grained `github_pat_`) | Prefix + body character set + length |
| `KindSlackToken` | Slack API tokens (`xoxb-`/`xoxp-`/`xoxa-`/`xoxo-`/`xoxr-`/`xoxs-`) | Prefix + type character + minimum body length |
| `KindGoogleAPIKey` | Google API keys (`AIza...`) | Prefix + 35-char body |
| `KindPrivateKeyPEM` | PEM private key headers (RSA/EC/DSA/OpenSSH/PKCS#8) | `-----BEGIN [ALGO ]PRIVATE KEY-----` header parse |
| `WithAll()` | All of the above | |

Detection does not establish that an account exists or that a credential authenticates. Scores are heuristics, not probabilities.

## Installation

```sh
go get github.com/nao1215/embargo
```

Requirements:

- Go 1.26.11 or later.
- Linux, macOS or Windows; the library also cross-builds for FreeBSD, OpenBSD and NetBSD.

The renamed module was first released as v0.3.0. The APIs below are on main pending the next release; to try them now, use `go get github.com/nao1215/embargo@main`.

## Scanning and masking

Use Scan for bytes, ScanString for text, or ScanLines for independent lines. Findings contain Kind, Start, End and Confidence; slice the original input when you need the matched value. Every overlap remains visible, ordered by position. ScanLines limits lines to 1 MiB and reports line-relative offsets.

Mask replaces the union of overlapping spans with [REDACTED]. MaskFunc accepts your replacement function, for example to keep a card's last four digits. Invalid ranges redact the entire input. See the [runnable examples](https://pkg.go.dev/github.com/nao1215/embargo#example-MaskFunc).

Implement Detector.Scan for application-specific tokens and add it with WithDetector. Custom detectors must return valid spans and scores, leave input unchanged, and support concurrent calls when shared.

## Values that must not be displayed

Secret hides its value from fmt, slog, JSON, text and XML output. Reveal deliberately returns the wrapped value. Input initializes a string or byte slice and rejects the redaction marker on round trips. These types do not erase memory or protect values after Reveal.

<!-- example: secret_example_test.go:ExampleNewSecret -->
```go
key := embargo.NewSecret("fake-key")
if _, err := fmt.Println(key); err != nil {
    panic(err)
}

// Output: [REDACTED]
```

## Mask logs

Wrap a standard slog handler to scan messages, keys, groups and values before they reach its writer. Pass NewScanner() for all built-ins or WithKinds to narrow detection. Any and error values become scanned strings; metadata and clean scalar types are preserved.

<!-- example: slog_example_test.go:ExampleNewSlogHandler -->
```go
package main

import (
 "log/slog"
 "os"

 "github.com/nao1215/embargo"
)

func main() {
	next := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attr
		},
	})
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	logger := slog.New(embargo.NewSlogHandler(next, scanner))
	logger.Info("checkout", "email", "alice@example.com", "card", "4532015112830366")

	// Output: level=INFO msg=checkout email=[REDACTED] card=[REDACTED]
}
```

## Check test output

Use embargotest to capture a writer, an HTTP response, or a test child process. Check requires output and a content expectation, then checks every capture for a known fake secret and detector findings. Narrow the scanner or allow exact fixture values when needed; canary checks remain active.

<!-- example: embargotest/example_integration_test.go:ExampleNew -->
```go
package main

import (
 "fmt"
 "log/slog"
 "testing"

 "github.com/nao1215/embargo"
 "github.com/nao1215/embargo/embargotest"
)

func main() {
	passed := false
	testing.Benchmark(func(b *testing.B) {
		b.Helper()
		recorder := embargotest.New(b)
		logger := slog.New(slog.NewJSONHandler(recorder.Writer("logs"), nil))
		logger.Info("accepted", "key", embargo.NewSecret(recorder.Canary()))
		//nolint:goconst // Self-contained examples show the actual display contract.
		recorder.ExpectJSON("logs", nil, map[string]string{"key": "[REDACTED]"}, 1)
		passed = recorder.Check()
	})

	if _, err := fmt.Println(passed); err != nil {
		panic(err)
	}

	// Output: true
}
```

In application tests pass `t` to `embargotest.New`; this standalone example uses a test benchmark to obtain a testing handle.

## Tested outputs

<!-- tested-outputs:start -->
| Output | How the test writes the secret | Checked result |
|---|---|---|
| fmt | `fmt.Fprintf(w, "%+#v", secret)` | `[REDACTED]` written, canary absent |
| slog TextHandler | `With("token", secret)` and a grouped attribute | `[REDACTED]` written, canary absent |
| slog JSONHandler | `With("token", secret)` and a grouped attribute | `[REDACTED]` written, canary absent |
| encoding/json | `json.NewEncoder(w).Encode(secret)` | `[REDACTED]` written, canary absent |
| encoding/xml | a struct field with an `xml` tag | `[REDACTED]` written, canary absent |
| text/template | `{{.}}` with the secret as data | `[REDACTED]` written, canary absent |
| zap JSON core | `zap.Any("token", secret)` | `[REDACTED]` written, canary absent |
| zerolog JSON | `Interface("token", secret)` | `[REDACTED]` written, canary absent |
| logrus JSON | `WithField("token", secret)` | `[REDACTED]` written, canary absent |
| OTel SDK | an exported span event and raw RecordError | expected attributes exported; raw canary and missing flush fail |
| Sentry | Secret in scope context, CaptureException and Recover | redacted event sent; raw canary and missing flush fail |
| HTTP | a real handler writing status, headers, body and trailers | expected response and marker; canary absent |
| Child panic | panic(secret) in a real test subprocess | panic marker and stack on stderr; canary absent |
<!-- tested-outputs:end -->

## Accuracy

These are exact-span results on a small labeled corpus, not a production accuracy claim. The corpus combines two synthetic/specification positives and two look-alikes per detector from [accuracy.json](tests/testdata/accuracy.json), with manually labeled original-byte ranges based on the existing recall fixtures, plus 16 shared [negative controls](tests/testdata/accuracy_controls.json): UUIDs, git SHAs, hashes, timestamps, order/shipment IDs, base64 and ordinary logs. Labels were assigned from the fixture's intended meaning, independently of scanner output. Ambiguous order IDs deliberately reuse card/ID-shaped digits. Each detector runs alone with default confidence; a true positive requires an unused expected range with exactly matching kind, start and end bytes. Partial, duplicate and extra findings count as false positives; unmatched expected spans count as false negatives. The corpus has no live personal data, no representative prevalence and little linguistic variety. Precision is TP/(TP+FP); recall is TP/(TP+FN); undefined ratios are n/a. Run `make accuracy-doc` to regenerate; CI rejects a stale table.

<!-- accuracy:start -->
| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |
|---|---:|---:|---:|---:|
| aba_routing | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| ach_trace | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| awskey | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| bank_account | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| btc | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| card_expiry | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| cvv | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| email | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| eth | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| github_token | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| google_api_key | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| iban | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| ipaddr | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| jwt | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| merchant_id | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| mynumber | 2 / 18 | 2 / 1 / 0 | 66.7% | 100.0% |
| pan | 2 / 18 | 2 / 1 / 0 | 66.7% | 100.0% |
| payment_token | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| phone_jp | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| private_key_pem | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| slack_token | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| swiftbic | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
| uk_sortcode | 2 / 18 | 2 / 0 / 0 | 100.0% | 100.0% |
<!-- accuracy:end -->

## Testing

Unit tests check formats, checksums and failure states. rapid generates shrinking property cases; metamorphic tests check offsets and redaction, and differential tests compare HTTP behavior with httptest and cryptographic checksums with independent implementations. Native Go fuzzing exercises scanning, masking, Input, canary encodings and JSON streams. gremlins mutates the implementation; API/panic goldens, runnable Examples, real logger/SDK compatibility and Linux/macOS/Windows CI cover the surrounding contracts. goleak checks child-process cleanup. Root dependencies remain zero; external test tools live in [tests/](tests/).

<!-- testing-metrics:start -->
Measured 2026-11-15 at [72e9a6a](https://github.com/nao1215/embargo/commit/72e9a6a0b0da5f55256eee8568d1eb304cfa270c): 96.7% statement coverage (2203/2278, root and integration suites combined); gremlins v0.6.0 with root-module tests, 4 workers and 10x baseline timeout: efficacy 86.79% (1353 killed, 206 lived, 110 uncovered, 34 timed out; mutator coverage 93.41%); 6 fuzz targets at 10 seconds each, 1442158 executions. Timeouts are reported separately and do not count as killed. These are dated measurements, not guarantees for arbitrary inputs.
<!-- testing-metrics:end -->

Run `go test ./...`, `go -C tests test ./...`, `make race`, `make fuzz`, `make mutation` and `make lint`. See [testing](doc/testing.md) for architecture checks and golden updates.

## Benchmarks

`make benchmark-doc` measures Scanner throughput for every detector and WithAll, masking, Recorder construction/capture/Check against a plain buffer, and the slog wrapper against a plain JSONHandler. Clean inputs contain ordinary text; dirty inputs use the synthetic positive corpus. Recorder figures include test cleanup registration. These are local measurements, not service latency predictions. The [raw samples](doc/benchmarks.raw.txt) and [manual benchstat comparison](doc/benchmarks.md) make the measurement reproducible; CI checks the rendered table, without noisy timing thresholds on shared runners.

<!-- benchmarks:start -->
Measured 2026-11-15 with go1.26.11, linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, GOMAXPROCS=1; median of five 200 ms samples at [4174a6a](https://github.com/nao1215/embargo/commit/4174a6a59e5bffcaacaf5212432846873cbc6e4c).

Background load: no intentional concurrent workload.

| Operation | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Scanner WithAll, clean | 95437.0 | 28.84 | 52480 | 131 |
| Scanner WithAll, dirty | 7532386.0 | 4.39 | 2397010 | 13186 |
| Mask | 6009.0 | 489.91 | 13816 | 12 |
| Writer only | 11.3 | 48196.88 | 0 | 0 |
| Recorder + Check | 80178.0 | 6.78 | 35637 | 509 |
| Plain slog, clean | 817.4 | — | 16 | 1 |
| Masked slog, clean | 4954.0 | — | 864 | 17 |
| Plain slog, dirty | 808.0 | — | 16 | 1 |
| Masked slog, dirty | 5740.0 | — | 1144 | 24 |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 496.03 | 35.43 |
| ach_trace | 928.27 | 9.12 |
| all | 28.84 | 4.39 |
| awskey | 1086.78 | 170.21 |
| bank_account | 1117.73 | 10.92 |
| btc | 1380.38 | 90.61 |
| card_expiry | 1312.22 | 0.74 |
| cvv | 520.48 | 5.19 |
| email | 70963.90 | 64.75 |
| eth | 1017.77 | 170.58 |
| github_token | 1699.29 | 246.58 |
| google_api_key | 1823.65 | 334.91 |
| iban | 1461.30 | 98.12 |
| ipaddr | 47223.18 | 45.84 |
| jwt | 1133.57 | 29.21 |
| merchant_id | 340.50 | 13.01 |
| mynumber | 251.85 | 51.64 |
| pan | 5025.22 | 42.81 |
| payment_token | 142.66 | 132.59 |
| phone_jp | 25268.77 | 43.71 |
| private_key_pem | 791.94 | 116.08 |
| slack_token | 1171.15 | 76.15 |
| swiftbic | 182.09 | 35.57 |
| uk_sortcode | 358.23 | 45.08 |

</details>
<!-- benchmarks:end -->

## Contributing

Bug reports, feature requests, and pull requests are welcome through [GitHub Issues](https://github.com/nao1215/embargo/issues) and [CONTRIBUTING.md](CONTRIBUTING.md). Use synthetic data in tests and see [CLAUDE.md](CLAUDE.md) for development rules. You can also [sponsor maintenance](https://github.com/sponsors/nao1215).

## License

[MIT License](LICENSE).

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
