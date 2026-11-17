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
| Scanner WithAll, clean | 56739.5 | 48.50 | 0 | 0 |
| Scanner WithAll, dirty | 6123671.0 | 10.39 | 1266448 | 4463 |
| Mask | 3024.5 | 973.41 | 8448 | 2 |
| Writer only | 5.5 | 99195.07 | 0 | 0 |
| Recorder + Check | 177317.0 | 3.07 | 229616 | 1678 |
| Plain slog, clean | 409.2 | — | 16 | 1 |
| Masked slog, clean | 1356.5 | — | 16 | 1 |
| Plain slog, dirty | 399.4 | — | 16 | 1 |
| Masked slog, dirty | 1552.5 | — | 64 | 2 |

Parallel: ns/op is wall time per event across all goroutines.

| Shared value | 1 CPU ns/op | 4 CPU ns/op | 16 CPU ns/op | Speed-up at 16 |
|---|---:|---:|---:|---:|
| Scanner.Scan | 3740.5 | 1033.5 | 318.3 | 11.8x |
| slog handler | 3252.5 | 938.3 | 390.6 | 8.3x |
| zap WriteSyncer | 6539.0 | 1807.5 | 849.5 | 7.7x |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 1129.43 | 127.22 |
| ach_trace | 1262.31 | 10.94 |
| all | 48.50 | 10.39 |
| awskey | 1055.94 | 293.65 |
| bank_account | 1175.47 | 13.47 |
| br_cnpj | 1103.86 | 169.81 |
| br_cpf | 1104.51 | 160.52 |
| btc | 1634.20 | 111.30 |
| ca_sin | 1070.42 | 163.74 |
| card_expiry | 2005.74 | 7.79 |
| cn_resident_id | 1512.55 | 71.47 |
| credential | 359.98 | 71.43 |
| cvv | 776.72 | 10.05 |
| email | 26771.50 | 201.24 |
| eth | 2374.56 | 364.85 |
| github_token | 2175.48 | 410.10 |
| google_api_key | 1848.65 | 470.53 |
| high_entropy | 1535.22 | 116.56 |
| iban | 538.29 | 138.54 |
| in_aadhaar | 1124.24 | 163.67 |
| in_pan | 1517.34 | 188.02 |
| ipaddr | 22468.53 | 73.00 |
| jwt | 2097.14 | 60.69 |
| kr_rrn | 1129.25 | 133.06 |
| merchant_id | 701.91 | 27.75 |
| mynumber | 1165.31 | 142.99 |
| pan | 8563.00 | 161.93 |
| payment_token | 304.04 | 413.46 |
| phone_jp | 22388.35 | 151.43 |
| phone_us | 9831.76 | 146.79 |
| private_key_pem | 1544.78 | 1512.72 |
| service_token | 62.09 | 324.88 |
| slack_token | 1893.07 | 224.47 |
| swiftbic | 382.43 | 114.82 |
| uk_nhs | 1167.80 | 173.62 |
| uk_nino | 1087.68 | 156.14 |
| uk_sortcode | 756.87 | 147.96 |
| us_itin | 1102.87 | 165.26 |
| us_ssn | 1105.20 | 178.66 |

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
