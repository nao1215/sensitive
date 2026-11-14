# Benchmarks

These historical measurements are from the commit below and are not measurements of the current release. Newer credential detectors are not included in the per-detector table.

Measurement conditions:

- Command: `go test -bench BenchmarkScanner -benchmem -benchtime 3s -count 5 -run '^$'`
- Go version: 1.24 (linux/amd64)
- GOMAXPROCS: 16
- CPU: AMD RYZEN AI MAX+ 395 w/ Radeon 8060S
- Commit: [b7e0cdc](https://github.com/nao1215/sensitive/commit/b7e0cdc)

To reproduce, run the command above. Use `-count 5` and take the median for stable results.
Benchmark numbers are environment-sensitive. Expect variation across Go versions, CPUs, and background load, and refresh results periodically if you publish them for compliance or audit purposes.

## Per-detector benchmarks (single detector enabled)

| Benchmark | ns/op | B/op | allocs/op |
|-----------|-------|------|-----------|
| PAN | 286.7 | 944 | 16 |
| Email | 188.2 | 288 | 9 |
| JPPhone | 171.3 | 464 | 8 |
| MyNumber | 142.0 | 392 | 6 |
| JWT | 1001 | 1208 | 25 |
| AWSKey | 147.1 | 280 | 8 |
| IBAN | 205.7 | 226 | 6 |
| IPAddr | 209.8 | 312 | 10 |
| SWIFTBIC | 176.1 | 288 | 9 |
| ABARouting | 132.7 | 376 | 6 |
| UKSortCode | 128.4 | 248 | 8 |
| CVV | 289.6 | 568 | 18 |
| CardExpiry | 261.4 | 456 | 16 |
| PaymentToken | 276.7 | 688 | 20 |
| BankAccount | 435.1 | 760 | 22 |
| ACHTrace | 325.9 | 480 | 17 |
| MerchantID | 343.4 | 568 | 18 |
| BTC | 514.5 | 328 | 7 |
| ETH | 2118 | 329 | 7 |

## Multi-detector and edge-case benchmarks

| Benchmark | Description |
|-----------|-------------|
| `BenchmarkScannerNoMatch` | All detectors enabled, input with no sensitive data. Note: detectors with nil hints (IBAN, SWIFT/BIC, ABA, MyNumber, BTC) always run regardless of input content. |
| `BenchmarkScannerAllDetectors` | All detectors enabled, input containing email + PAN + IP |
| `BenchmarkScannerEmptyInput` | All detectors enabled, nil input |
| `BenchmarkScannerLargeInput` | All detectors enabled, ~4KB log block with no sensitive data |
| `BenchmarkScannerHintMatchNoDetection` | All detectors enabled, hints match but no valid sensitive data found |
| `BenchmarkScannerFullWidthInput` | All detectors enabled, full-width digit input requiring normalization |
