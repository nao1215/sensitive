# Benchmarks

Run `make benchmark-doc` on an idle machine. It uses Go 1.26.11, GOMAXPROCS=1 and ten 200 ms samples, stores every sample in benchmarks.raw.txt and the medians with machine/source metadata in benchmarks.json, then regenerates the full benchmark plot and this page’s tables. Scanner benchmarks cover clean text and each detector's synthetic positive fixture, plus WithAll over all positive fixtures. Mask uses precomputed findings. Recorder includes creation, a writer, an expectation, Check and testing cleanup registration. The slog comparison uses a real JSONHandler and a counting sink, so encoding work is present in both the plain and wrapped measurements.

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
| Scanner WithAll, clean | 62241.5 | 44.21 | 0 | 0 |
| Scanner WithAll, dirty | 6963340.0 | 9.14 | 1431824 | 11824 |
| Mask | 3188.5 | 923.39 | 8448 | 2 |
| Writer only | 5.7 | 95223.85 | 0 | 0 |
| Recorder + Check | 48863.0 | 11.13 | 45899 | 686 |
| Plain slog, clean | 433.0 | — | 16 | 1 |
| Masked slog, clean | 1424.5 | — | 16 | 1 |
| Plain slog, dirty | 432.8 | — | 16 | 1 |
| Masked slog, dirty | 1673.0 | — | 64 | 2 |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 1093.43 | 122.59 |
| ach_trace | 1208.40 | 10.50 |
| all | 44.21 | 9.14 |
| awskey | 1408.92 | 280.17 |
| bank_account | 1123.44 | 12.76 |
| br_cnpj | 1059.66 | 165.84 |
| br_cpf | 1057.92 | 167.66 |
| btc | 1585.49 | 105.07 |
| ca_sin | 1041.91 | 163.05 |
| card_expiry | 1960.53 | 7.51 |
| cn_resident_id | 1414.99 | 69.40 |
| credential | 387.08 | 72.19 |
| cvv | 745.46 | 9.79 |
| email | 28164.93 | 187.88 |
| eth | 2332.98 | 347.99 |
| github_token | 2115.89 | 395.15 |
| google_api_key | 1819.28 | 460.87 |
| high_entropy | 1604.89 | 112.28 |
| iban | 520.04 | 129.75 |
| in_aadhaar | 1073.12 | 162.93 |
| in_pan | 1435.17 | 188.60 |
| ipaddr | 22860.57 | 71.85 |
| jwt | 2032.79 | 58.69 |
| kr_rrn | 1071.76 | 136.11 |
| merchant_id | 669.42 | 27.23 |
| mynumber | 1108.85 | 120.18 |
| pan | 8469.68 | 157.08 |
| payment_token | 288.12 | 391.79 |
| phone_jp | 22292.28 | 127.23 |
| phone_us | 9825.12 | 122.93 |
| private_key_pem | 1487.45 | 1580.54 |
| service_token | 482.39 | 506.63 |
| slack_token | 1822.32 | 213.50 |
| swiftbic | 367.07 | 111.48 |
| uk_nhs | 1119.26 | 170.91 |
| uk_nino | 1028.53 | 155.11 |
| uk_sortcode | 803.50 | 140.27 |
| us_itin | 1041.16 | 173.36 |
| us_ssn | 1043.66 | 177.29 |

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
| all | 64,763.000 | 6,837,398.5 | 1.00× / 1.00× |
| kinds1 | 101.000 | 22,310.0 | 641.22× / 306.47× |
| kinds3 | 8,648.500 | 496,620.0 | 7.49× / 13.77× |
| kinds8 | 10,173.500 | 1,541,041.5 | 6.37× / 4.44× |
<!-- narrowing:end -->

The one-kind set is email; three kinds add PAN and credential; eight add Japanese phone, IP address, GitHub token, service token and private-key PEM. Omitting kinds gives up their recall. Select kinds according to the application's output policy and inspect the [real-log false-positive estimates](accuracy.md#public-system-logs).

These dated samples ran ten times with alternating kind order, Go 1.26.11 and GOMAXPROCS=1 on one host. They describe that recorded fixture and implementation, not the current release's universal performance. [Raw samples](performance/scanner-narrowing.raw.txt) retain the variation. Run `make scanner-experiment CPU=8` on an idle Linux machine to refresh the samples; `python3 scripts/scanner_experiment.py --check` only checks the committed table.
