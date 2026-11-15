# embargo

embargo detects and masks personal data, payment data and secrets in text, with zero dependencies and cross-platform support.

[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/embargo.svg)](https://pkg.go.dev/github.com/nao1215/embargo)
![Coverage](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/embargo/coverage.svg)
[![MultiPlatformUnitTest](https://github.com/nao1215/embargo/actions/workflows/unit_test.yml/badge.svg)](https://github.com/nao1215/embargo/actions/workflows/unit_test.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/nao1215/embargo/badge)](https://scorecard.dev/viewer/?uri=github.com/nao1215/embargo)

![logo](./doc/images/logo-small.png)

## Quick start

<!-- example: example_test.go:Example -->
```go
text := "email=alice@example.com card=4111111111111111"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	if _, err := fmt.Println(embargo.Mask(text, scanner.ScanString(text))); err != nil {
		panic(err)
	}
	// Output: email=[REDACTED] card=[REDACTED]
```

NewScanner() and WithAll() enable every built-in, including IP addresses and context-based detectors. Use WithKinds to narrow the selection. Findings retain all overlaps and contain byte offsets rather than raw values.

## Why embargo?

Logs, support messages, and imported text can contain payment details, personal data, or credentials. embargo finds their locations so your Go program can flag, classify, or mask them before forwarding the text.

Dedicated parsers and checksum checks help distinguish candidates from ordinary text, including Japanese phone numbers and My Number. Detection results remain available when you need your own handling policy.

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

## Installation and requirements

In an existing Go module, run `go get github.com/nao1215/embargo`. The library requires Go 1.26.11 or later and is tested on Linux, macOS, and Windows.

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

## Testing

The library has zero dependencies; test-only tools live in the separate [tests/](tests/) module (Go 1.26.11+). Run `go test ./...` in both directories; this executes the Go examples and checks README snippets against them. See [testing](doc/testing.md) for lint, vet, fuzzing, golden updates, coverage, and mutation checks.

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

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
