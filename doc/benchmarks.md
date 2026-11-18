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
Measured 2026-11-17 with go1.26.11, linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, GOMAXPROCS=1; median of ten 200 ms samples.

Background load: no intentional concurrent workload.

| Operation | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Scanner WithAll, clean | 56809.5 | 48.44 | 0 | 0 |
| Scanner WithAll, dirty | 6167476.5 | 10.32 | 1266448 | 4463 |
| Mask | 3089.0 | 953.14 | 8448 | 2 |
| Writer only | 5.6 | 97918.29 | 0 | 0 |
| Recorder + Check | 178906.0 | 3.04 | 229617 | 1678 |
| Plain slog, clean | 414.4 | — | 16 | 1 |
| Masked slog, clean | 1355.5 | — | 16 | 1 |
| Plain slog, dirty | 422.8 | — | 16 | 1 |
| Masked slog, dirty | 1576.5 | — | 64 | 2 |

Parallel: ns/op is wall time per event across all goroutines.

| Shared value | 1 CPU ns/op | 4 CPU ns/op | 16 CPU ns/op | Speed-up at 16 |
|---|---:|---:|---:|---:|
| Scanner.Scan | 3792.0 | 1052.5 | 347.8 | 10.9x |
| slog handler | 3260.5 | 934.7 | 360.0 | 9.1x |
| zap WriteSyncer | 6497.0 | 1833.0 | 964.5 | 6.7x |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 1149.43 | 127.61 |
| ach_trace | 1270.49 | 10.86 |
| all | 48.44 | 10.32 |
| awskey | 1062.89 | 294.21 |
| bank_account | 1174.01 | 13.35 |
| br_cnpj | 1069.30 | 171.47 |
| br_cpf | 1095.70 | 166.87 |
| btc | 1618.16 | 107.62 |
| ca_sin | 1069.82 | 162.91 |
| card_expiry | 2019.93 | 7.86 |
| cn_resident_id | 1487.51 | 71.14 |
| credential | 361.61 | 70.10 |
| cvv | 769.50 | 10.09 |
| email | 26682.06 | 195.95 |
| eth | 2370.80 | 363.91 |
| github_token | 2176.77 | 405.17 |
| google_api_key | 1860.94 | 465.08 |
| high_entropy | 1523.93 | 114.30 |
| iban | 535.18 | 137.81 |
| in_aadhaar | 1114.25 | 165.62 |
| in_pan | 1513.20 | 186.90 |
| ipaddr | 23591.17 | 72.48 |
| jwt | 2116.36 | 60.27 |
| kr_rrn | 1116.68 | 123.12 |
| merchant_id | 698.03 | 26.96 |
| mynumber | 1164.36 | 141.68 |
| pan | 8476.94 | 158.68 |
| payment_token | 303.37 | 404.78 |
| phone_jp | 22410.58 | 150.31 |
| phone_us | 9739.88 | 148.57 |
| private_key_pem | 1539.14 | 1514.75 |
| service_token | 61.79 | 297.55 |
| slack_token | 1879.79 | 222.35 |
| swiftbic | 375.39 | 114.24 |
| uk_nhs | 1172.28 | 170.08 |
| uk_nino | 1080.38 | 155.05 |
| uk_sortcode | 746.27 | 147.15 |
| us_itin | 1088.74 | 165.64 |
| us_ssn | 1093.55 | 175.47 |

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
