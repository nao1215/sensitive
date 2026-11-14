# sensitive

sensitive detects sensitive data in text and returns its type, byte positions, and confidence, with optional masking.

[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/sensitive.svg)](https://pkg.go.dev/github.com/nao1215/sensitive)
![Coverage](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/sensitive/coverage.svg)
[![MultiPlatformUnitTest](https://github.com/nao1215/sensitive/actions/workflows/unit_test.yml/badge.svg)](https://github.com/nao1215/sensitive/actions/workflows/unit_test.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/nao1215/sensitive/badge)](https://scorecard.dev/viewer/?uri=github.com/nao1215/sensitive)

![logo](./doc/images/logo-small.png)

## Try it in 30 seconds

Save this as `main.go` in a new directory:

<!-- example: example_test.go:Example -->
```go
package main

import (
	"fmt"

	"github.com/nao1215/sensitive"
)

func main() {
	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
	text := "user tanaka@example.com paid with 4532015112830366"
	for _, f := range scanner.ScanString(text) {
		fmt.Printf("%s: %s (%.2f)\n", f.DetectorName, f.RawValue, f.Confidence)
	}
	// Output:
	// pan: 4532015112830366 (1.00)
	// email: tanaka@example.com (1.00)
}
```

```sh
go mod init example.com/scan
go get github.com/nao1215/sensitive
go run .
```

This uses a test card number and an `example.com` address. Choose detectors explicitly as above; [NewScanner](https://pkg.go.dev/github.com/nao1215/sensitive#NewScanner) shows empty, selected, and all-detector configurations.

## Why sensitive?

Logs, support messages, and imported text can contain payment details, personal data, or credentials. sensitive finds their locations so your Go program can flag, classify, or mask them before forwarding the text.

Dedicated parsers and checksum checks help distinguish candidates from ordinary text, including Japanese phone numbers and My Number. Detection results remain available when you need your own handling policy.

## Supported detectors

| Option | Detects | Validation |
|--------|---------|------------|
| `WithPAN()` | Credit card numbers (Visa, Mastercard, Amex, JCB, Discover, Diners, UnionPay) | BIN prefix + Luhn algorithm |
| `WithEmail()` | Email addresses | Structure + known TLD check |
| `WithJPPhone()` | Japanese phone numbers (mobile, landline, IP phone, toll-free, M2M/IoT, service) | Prefix classification + digit count |
| `WithMyNumber()` | Japanese My Number (12-digit individual number) | MOD 11 check digit |
| `WithJWT()` | JSON Web Tokens | Header decode + `alg` key check |
| `WithAWSKey()` | AWS Access Key IDs (`AKIA...` / `ASIA...`) | Prefix + 20-char alphanumeric |
| `WithIBAN()` | International Bank Account Numbers | Country code + MOD 97 check digit |
| `WithIPAddr()` | IPv4 and IPv6 addresses | `net.ParseIP` + octet range |
| `WithSWIFTBIC()` | SWIFT/BIC codes | Format + country code validation |
| `WithABARouting()` | US ABA routing numbers | Prefix range + checksum |
| `WithUKSortCode()` | UK sort codes (XX-XX-XX) | Pattern + boundary checks |
| `WithCVV()` | Card verification values (CVV/CVC/CID) | Context keyword + digit length (context-based, weaker) |
| `WithCardExpiry()` | Card expiration dates | Context keyword + MM/YY validation (context-based, weaker) |
| `WithPaymentToken()` | Payment processor tokens (Stripe/PayPal/Square) | Prefix + minimum body length |
| `WithBankAccount()` | Bank account numbers (context-based) | Context keyword + digit range (context-based, weaker) |
| `WithACHTrace()` | ACH trace numbers | Context keyword + prefix range (context-based, weaker) |
| `WithMerchantID()` | Merchant/terminal IDs | Context keyword + format (context-based, weaker) |
| `WithBTC()` | Bitcoin addresses (P2PKH, P2SH, Bech32, Bech32m/Taproot) | Base58Check (double SHA-256) / Bech32 polynomial checksum |
| `WithETH()` | Ethereum addresses (0x + 40 hex) | EIP-55 mixed-case checksum (Keccak-256) |
| `WithGitHubToken()` | GitHub tokens (classic `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, fine-grained `github_pat_`) | Prefix + body character set + length |
| `WithSlackToken()` | Slack API tokens (`xoxb-`/`xoxp-`/`xoxa-`/`xoxo-`/`xoxr-`/`xoxs-`) | Prefix + type character + minimum body length |
| `WithGoogleAPIKey()` | Google API keys (`AIza...`) | Prefix + 35-char body |
| `WithPrivateKeyPEM()` | PEM private key headers (RSA/EC/DSA/OpenSSH/PKCS#8) | `-----BEGIN [ALGO ]PRIVATE KEY-----` header parse |
| `WithAll()` | All of the above | |

The table summarizes validation; each [detector type](https://pkg.go.dev/github.com/nao1215/sensitive/detector) documents its exact acceptance rules and score. Detection does not establish that an account exists or that a credential authenticates. [WithAll](https://pkg.go.dev/github.com/nao1215/sensitive#WithAll) includes context-based matches; use individual options when false positives are costly.

## Installation and requirements

In an existing Go module, run `go get github.com/nao1215/sensitive`. The library requires Go 1.22 or later and is tested on Linux, macOS, and Windows.

## Scan bytes, strings, or streams

Use [Scan](https://pkg.go.dev/github.com/nao1215/sensitive#Scanner.Scan) for `[]byte`, [ScanString](https://pkg.go.dev/github.com/nao1215/sensitive#Scanner.ScanString) for strings, or [ScanReader](https://pkg.go.dev/github.com/nao1215/sensitive#Scanner.ScanReader) for a reader whose content fits in memory. For line-oriented logs, import `strings` and use [ScanLines](https://pkg.go.dev/github.com/nao1215/sensitive#Scanner.ScanLines):

<!-- example: example_test.go:ExampleScanner_ScanLines -->
```go
scanner := sensitive.NewScanner(sensitive.WithEmail())
input := "safe line\nadmin@example.com\n"
err := scanner.ScanLines(strings.NewReader(input), func(n int, line []byte, findings []sensitive.Finding) {
	for _, f := range findings {
		fmt.Printf("line %d [%d:%d]: %s\n", n, f.Start, f.End, line[f.Start:f.End])
	}
})
if err != nil {
	fmt.Println("error:", err)
}
// Output:
// line 2 [0:17]: admin@example.com
```

The method docs specify line limits, offsets, callback lifetime, and read errors. The [package documentation](https://pkg.go.dev/github.com/nao1215/sensitive) explains the scanning pipeline; [benchmarks](doc/benchmarks.md) record its measurements.

## Work with findings

[Finding](https://pkg.go.dev/github.com/nao1215/sensitive/detector#Finding) exposes the matched value and detector-specific detail. Use `Is` or an `Is*` method to select a detector, `Kind` to classify financial data, PII, or credentials, and typed accessors such as `PANDetail` to read metadata without a direct type assertion.

The [detail example](https://pkg.go.dev/github.com/nao1215/sensitive/detector#example-Finding.PANDetail) shows brand and last-four access. [Scanner options](https://pkg.go.dev/github.com/nao1215/sensitive#example-NewScanner-Options) show how to retain overlapping matches and order findings by position. [Full-width digit support](https://pkg.go.dev/github.com/nao1215/sensitive/detector#hdr-Full_Width_Digits_and_Boundaries) lists the detectors that normalize Japanese numeric text.

## Filter by confidence

[WithMinConfidence](https://pkg.go.dev/github.com/nao1215/sensitive#WithMinConfidence) selects the results to keep:

<!-- example: example_test.go:ExampleWithMinConfidence -->
```go
text := "user tanaka@example.com bank account 12345678"
for _, threshold := range []float64{0.4, 0.8} {
	scanner := sensitive.NewScanner(
		sensitive.WithEmail(), sensitive.WithBankAccount(),
		sensitive.WithMinConfidence(threshold),
	)
	fmt.Printf("threshold %.1f: %d findings\n", threshold, len(scanner.ScanString(text)))
}
// Output:
// threshold 0.4: 2 findings
// threshold 0.8: 1 findings
```

Read the [confidence model](https://pkg.go.dev/github.com/nao1215/sensitive#hdr-Confidence) before using the score as a policy; `Finding.Level` offers named categories when an exact number is unnecessary.

## Mask findings

Import `detector` and `mask` alongside `sensitive` to assign a strategy to each detector:

<!-- example: mask/example_test.go:ExampleMask -->
```go
scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
text := "user tanaka@example.com paid with 4532015112830366"
findings := scanner.ScanString(text)

// Apply different masking strategies per detector.
masked := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{
	detector.NamePAN:   mask.Last4,
	detector.NameEmail: mask.Partial,
})

fmt.Println(masked)
// Output:
// user t*****@example.com paid with ************0366
```

[MaskAll](https://pkg.go.dev/github.com/nao1215/sensitive/mask#MaskAll) applies one strategy to every finding. The [strategy example](https://pkg.go.dev/github.com/nao1215/sensitive/mask#example-Mask-Strategies) compares `Redact`, `Last4`, `First1Last4`, `Partial`, and `Hash`; their docs specify what remains visible and how overlaps are handled.

## Add a detector

Use [WithDetector](https://pkg.go.dev/github.com/nao1215/sensitive#example-WithDetector) with `detector.NewRegex` for a custom pattern such as a ticket ID. For domain validation, implement [Detector](https://pkg.go.dev/github.com/nao1215/sensitive/detector#Detector). The [custom detector guide](https://pkg.go.dev/github.com/nao1215/sensitive#hdr-Custom_Detectors) explains hint selection and links the runnable example.

## Testing

The library has zero dependencies; test-only tools live in the separate [tests/](tests/) module (Go 1.23+). Run `go test ./...` in both directories; this executes the Go examples and checks README snippets against them. See [testing](doc/testing.md) for lint, vet, fuzzing, golden updates, coverage, and mutation checks.

## Contributing

Bug reports, feature requests, and pull requests are welcome through [GitHub Issues](https://github.com/nao1215/sensitive/issues) and [CONTRIBUTING.md](CONTRIBUTING.md). Use synthetic data in tests and see [CLAUDE.md](CLAUDE.md) for development rules. You can also [sponsor maintenance](https://github.com/sponsors/nao1215).

## License

[MIT License](LICENSE).

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/en/reference/emoji-key/)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://debimate.jp/"><img src="https://avatars.githubusercontent.com/u/22737008?v=4?s=75" width="75px;" alt="CHIKAMATSU Naohiro"/><br /><sub><b>CHIKAMATSU Naohiro</b></sub></a><br /><a href="https://github.com/nao1215/sensitive/commits?author=nao1215" title="Code">💻</a> <a href="https://github.com/nao1215/sensitive/commits?author=nao1215" title="Documentation">📖</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
