# Benchmarks

Run `make benchmark-doc` on an idle machine. It uses Go 1.26.11, GOMAXPROCS=1 and ten 200 ms samples, stores every sample in benchmarks.raw.txt and the medians with machine/source metadata in benchmarks.json, then regenerates the full benchmark plot and this page’s tables. Scanner benchmarks cover clean text and each detector's synthetic positive fixture, plus WithAll over all positive fixtures. Mask uses precomputed findings. Recorder includes creation, a writer, an expectation, Check and testing cleanup registration. The slog comparison uses a real JSONHandler and a counting sink, so encoding work is present in both the plain and wrapped measurements. The parallel table shares one scanner, one slog logger and one zap logger among 1, 4 and 16 goroutines with GOMAXPROCS set to the same number, which is how a service uses them.

Shared CI runners have variable load. CI compiles benchmarks and checks the table against its recorded samples; it does not impose a noisy wall-time threshold. Compare base and head manually on the same idle machine and retain both outputs; the comparison should alternate runs to reduce time-order bias:

```sh
git worktree add ../embargo-benchmark-base "$(git merge-base HEAD origin/main)"
GOMAXPROCS=1 GOTOOLCHAIN=go1.26.11 go -C ../embargo-benchmark-base/tests test -run '^$' -bench '^BenchmarkPublished' -benchmem -count=10 . > base.txt
GOMAXPROCS=1 GOTOOLCHAIN=go1.26.11 go -C tests test -run '^$' -bench '^BenchmarkPublished' -benchmem -count=10 . > head.txt
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e base.txt head.txt
```

Use a base that contains these benchmark names and a compatible API. The first benchmark publication has no comparable base for the newly introduced recorder and slog wrapper. Keep timing differences separate from allocations and throughput, and inspect confidence intervals before drawing conclusions.

![Full scanner throughput and slog time](images/benchmarks.svg)

## Measured results

<!-- benchmarks:start -->
Measured 2026-11-18 with go1.26.11, linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, GOMAXPROCS=1; median of ten 200 ms samples.

Background load: no intentional concurrent workload.

| Operation | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Scanner WithAll, clean | 62022.0 | 44.37 | 0 | 0 |
| Scanner WithAll, dirty | 6861085.0 | 9.15 | 1166864 | 3489 |
| Mask | 3239.5 | 908.70 | 8448 | 2 |
| Writer only | 6.4 | 84435.41 | 0 | 0 |
| Recorder + Check | 239464.0 | 2.27 | 236638 | 1608 |
| Plain slog, clean | 509.7 | — | 16 | 1 |
| Masked slog, clean | 1015.0 | — | 16 | 1 |
| Plain slog, dirty | 425.3 | — | 16 | 1 |
| Masked slog, dirty | 1165.0 | — | 16 | 1 |

Parallel: ns/op is wall time per event across all goroutines.

| Shared value | 1 CPU ns/op | 4 CPU ns/op | 16 CPU ns/op | 16 CPU vs 1 CPU |
|---|---:|---:|---:|---:|
| Scanner.Scan | 4798.0 | 1257.0 | 477.9 | 10.0x faster |
| slog handler | 1804.0 | 552.2 | 231.9 | 7.8x faster |
| zap WriteSyncer | 5235.0 | 2022.0 | 1140.0 | 4.6x faster |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 1110.01 | 75.31 |
| ach_trace | 799.36 | 37.17 |
| all | 44.37 | 9.15 |
| awskey | 730.65 | 248.25 |
| bank_account | 781.55 | 42.06 |
| br_cnpj | 753.32 | 125.39 |
| br_cpf | 794.85 | 125.28 |
| btc | 1151.09 | 105.33 |
| ca_sin | 781.92 | 131.63 |
| card_expiry | 1071.18 | 17.76 |
| cn_resident_id | 1018.74 | 62.32 |
| credential | 270.75 | 66.52 |
| cvv | 577.38 | 22.19 |
| email | 3365.80 | 178.19 |
| eth | 1174.02 | 311.35 |
| github_token | 1123.62 | 339.03 |
| google_api_key | 1026.24 | 384.77 |
| high_entropy | 1124.24 | 112.16 |
| iban | 474.89 | 128.95 |
| in_aadhaar | 799.69 | 142.33 |
| in_pan | 1028.26 | 134.43 |
| ipaddr | 3390.53 | 67.70 |
| jwt | 1098.04 | 58.34 |
| kr_rrn | 800.78 | 102.64 |
| merchant_id | 531.50 | 72.29 |
| mynumber | 1116.80 | 111.81 |
| pan | 2721.55 | 102.25 |
| payment_token | 267.17 | 324.98 |
| phone_jp | 3301.34 | 89.88 |
| phone_us | 2828.25 | 139.08 |
| private_key_pem | 920.15 | 763.69 |
| service_token | 57.76 | 263.81 |
| slack_token | 971.77 | 180.78 |
| swiftbic | 288.48 | 95.65 |
| uk_nhs | 715.22 | 126.67 |
| uk_nino | 778.42 | 98.10 |
| uk_sortcode | 525.11 | 109.37 |
| us_itin | 658.21 | 114.95 |
| us_ssn | 624.72 | 114.48 |

</details>
<!-- benchmarks:end -->

## Candidate windows and dispatch

Production scanning uses hint dispatch and validates complete candidate boundaries. The test-only candidate-window prototype in scanner_dispatch_test.go cannot bound arbitrary credential values or PEM bodies: long assignments, PEM bodies and provider tokens cross its fixed windows. TestCandidateExperimentGate checks exact kinds, offsets, confidence and order against the production scanner and retains those disqualifying cases. Run it with EMBARGO_LOG_CACHE pointing to the checksum-pinned corpus to include real log lines. No timing improvement is claimed for the prototype.

Reuse Scanner across events to amortize immutable dispatch construction. Percent-encoded inputs need a decoded buffer and an original-position map; ordinary inputs avoid those buffers. Single-detector scans retain substring selection, while multi-detector scans use hint buckets.

## Choose the kinds the application needs

WithKinds avoids running irrelevant detectors and removes their false-positive findings. The following measurements use identical input for all selections: 2,752 bytes of clean worker text and 39,552 bytes containing every detector's synthetic positive fixture. They measure scanning only, not logger encoding. The clean fixture has no @, so email-only scanning exits after a substring check; its ratio should not be extrapolated to arbitrary logs.

<!-- narrowing:start -->
| Selection | Clean ns/op | Dirty ns/op | Clean / dirty speedup over WithAll |
|---|---:|---:|---|
| all | 64,763 | 6,837,398 | 1.00× / 1.00× |
| kinds1 | 101 | 22,310 | 641.22× / 306.47× |
| kinds3 | 8,648 | 496,620 | 7.49× / 13.77× |
| kinds8 | 10,174 | 1,541,042 | 6.37× / 4.44× |
<!-- narrowing:end -->

The one-kind set is email; three kinds add PAN and credential; eight add Japanese phone, IP address, GitHub token, service token and private-key PEM. Omitting kinds gives up their recall. Select kinds according to the application's output policy and inspect the [real-log false-positive estimates](accuracy.md#public-system-logs).

These dated samples ran ten times with alternating kind order, Go 1.26.11 and GOMAXPROCS=1 on one host. They describe that recorded fixture and implementation, not the current release's universal performance. [Raw samples](performance/scanner-narrowing.raw.txt) retain the variation. Run `make scanner-experiment CPU=8` on an idle Linux machine to refresh the samples; `python3 scripts/scanner_experiment.py --check` only checks the committed table.
