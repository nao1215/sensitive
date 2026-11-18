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
| Scanner WithAll, clean | 54676.5 | 50.33 | 0 | 0 |
| Scanner WithAll, dirty | 6283157.0 | 9.99 | 1166864 | 3489 |
| Mask | 3230.0 | 911.37 | 8448 | 2 |
| Writer only | 5.7 | 94985.53 | 0 | 0 |
| Recorder + Check | 200958.0 | 2.71 | 236632 | 1608 |
| Plain slog, clean | 432.0 | — | 16 | 1 |
| Masked slog, clean | 853.1 | — | 16 | 1 |
| Plain slog, dirty | 432.0 | — | 16 | 1 |
| Masked slog, dirty | 1101.5 | — | 16 | 1 |

Parallel: ns/op is wall time per event across all goroutines.

| Shared value | 1 CPU ns/op | 4 CPU ns/op | 16 CPU ns/op | Speed-up at 16 |
|---|---:|---:|---:|---:|
| Scanner.Scan | 4458.0 | 4497.0 | 4581.5 | 1.0x |
| slog handler | 1788.5 | 1802.5 | 1817.0 | 1.0x |
| zap WriteSyncer | 4500.0 | 4790.0 | 5135.0 | 0.9x |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 1050.56 | 74.17 |
| ach_trace | 777.36 | 36.15 |
| all | 50.33 | 9.99 |
| awskey | 690.15 | 238.39 |
| bank_account | 741.37 | 40.66 |
| br_cnpj | 757.85 | 124.56 |
| br_cpf | 758.13 | 120.89 |
| btc | 1103.26 | 101.12 |
| ca_sin | 746.81 | 126.80 |
| card_expiry | 1024.57 | 17.31 |
| cn_resident_id | 981.25 | 59.21 |
| credential | 259.85 | 64.70 |
| cvv | 552.06 | 21.47 |
| email | 3208.61 | 173.24 |
| eth | 1115.07 | 293.69 |
| github_token | 1060.89 | 323.06 |
| google_api_key | 981.11 | 368.55 |
| high_entropy | 1073.49 | 107.62 |
| iban | 457.82 | 123.60 |
| in_aadhaar | 764.62 | 138.05 |
| in_pan | 982.12 | 128.65 |
| ipaddr | 3214.51 | 65.85 |
| jwt | 1050.37 | 56.80 |
| kr_rrn | 766.46 | 97.72 |
| merchant_id | 514.87 | 69.78 |
| mynumber | 1065.63 | 107.22 |
| pan | 2596.66 | 97.98 |
| payment_token | 255.73 | 311.10 |
| phone_jp | 3143.80 | 85.96 |
| phone_us | 2693.20 | 133.22 |
| private_key_pem | 886.50 | 948.34 |
| service_token | 56.76 | 272.44 |
| slack_token | 985.17 | 183.85 |
| swiftbic | 287.08 | 102.94 |
| uk_nhs | 788.33 | 140.54 |
| uk_nino | 751.36 | 110.19 |
| uk_sortcode | 602.81 | 128.25 |
| us_itin | 753.07 | 134.70 |
| us_ssn | 751.21 | 137.36 |

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
