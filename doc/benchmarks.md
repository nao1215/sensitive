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
| Scanner WithAll, clean | 52642.5 | 52.28 | 0 | 0 |
| Scanner WithAll, dirty | 6208059.0 | 10.11 | 1166864 | 3489 |
| Mask | 3223.0 | 913.53 | 8448 | 2 |
| Writer only | 5.7 | 94932.14 | 0 | 0 |
| Recorder + Check | 197466.5 | 2.75 | 236425 | 1604 |
| Plain slog, clean | 432.9 | — | 16 | 1 |
| Masked slog, clean | 875.8 | — | 16 | 1 |
| Plain slog, dirty | 421.5 | — | 16 | 1 |
| Masked slog, dirty | 1195.5 | — | 64 | 2 |

Parallel: ns/op is wall time per event across all goroutines.

| Shared value | 1 CPU ns/op | 4 CPU ns/op | 16 CPU ns/op | Speed-up at 16 |
|---|---:|---:|---:|---:|
| Scanner.Scan | 4227.0 | 4217.5 | 4235.0 | 1.0x |
| slog handler | 1989.5 | 2066.5 | 2085.0 | 1.0x |
| zap WriteSyncer | 4705.0 | 5163.0 | 5318.5 | 0.9x |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 1725.61 | 75.72 |
| ach_trace | 985.94 | 38.98 |
| all | 52.28 | 10.11 |
| awskey | 846.05 | 263.71 |
| bank_account | 931.09 | 44.24 |
| br_cnpj | 958.18 | 128.16 |
| br_cpf | 956.85 | 124.56 |
| btc | 1428.37 | 105.17 |
| ca_sin | 931.79 | 133.48 |
| card_expiry | 1418.54 | 17.57 |
| cn_resident_id | 1291.59 | 56.55 |
| credential | 327.50 | 68.31 |
| cvv | 649.07 | 22.77 |
| email | 18600.88 | 184.38 |
| eth | 1604.47 | 320.87 |
| github_token | 1501.92 | 354.37 |
| google_api_key | 1329.43 | 401.88 |
| high_entropy | 1462.35 | 109.72 |
| iban | 524.42 | 126.21 |
| in_aadhaar | 961.90 | 141.18 |
| in_pan | 1293.03 | 135.49 |
| ipaddr | 18667.23 | 68.23 |
| jwt | 1454.44 | 56.32 |
| kr_rrn | 962.12 | 103.07 |
| merchant_id | 595.28 | 72.70 |
| mynumber | 1716.88 | 110.80 |
| pan | 7787.56 | 102.18 |
| payment_token | 274.72 | 348.44 |
| phone_jp | 15406.21 | 88.79 |
| phone_us | 8817.94 | 138.26 |
| private_key_pem | 1151.43 | 1249.40 |
| service_token | 57.80 | 297.37 |
| slack_token | 1335.32 | 194.05 |
| swiftbic | 301.61 | 105.87 |
| uk_nhs | 994.88 | 150.20 |
| uk_nino | 921.76 | 114.30 |
| uk_sortcode | 703.48 | 132.81 |
| us_itin | 933.63 | 141.58 |
| us_ssn | 893.56 | 141.40 |

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
