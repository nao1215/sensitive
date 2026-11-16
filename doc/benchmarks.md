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
Measured 2026-11-15 with go1.26.11, linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, GOMAXPROCS=1; median of ten 200 ms samples.

Background load: no intentional concurrent workload.

| Operation | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Scanner WithAll, clean | 67131.5 | 41.00 | 0 | 0 |
| Scanner WithAll, dirty | 8091315.0 | 4.89 | 1187111 | 14113 |
| Mask | 6306.5 | 466.82 | 13816 | 12 |
| Writer only | 11.5 | 47214.50 | 0 | 0 |
| Recorder + Check | 76069.5 | 7.15 | 40396 | 590 |
| Plain slog, clean | 866.2 | — | 16 | 1 |
| Masked slog, clean | 2477.0 | — | 80 | 5 |
| Plain slog, dirty | 875.1 | — | 16 | 1 |
| Masked slog, dirty | 3422.0 | — | 352 | 13 |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 547.43 | 46.56 |
| ach_trace | 699.91 | 4.88 |
| all | 41.00 | 4.89 |
| awskey | 731.00 | 95.30 |
| bank_account | 569.69 | 6.16 |
| btc | 728.13 | 45.03 |
| card_expiry | 1007.12 | 3.72 |
| credential | 275.76 | 47.54 |
| cvv | 366.88 | 4.92 |
| email | 25480.33 | 58.70 |
| eth | 1215.56 | 144.50 |
| github_token | 1125.67 | 125.61 |
| google_api_key | 937.89 | 176.08 |
| high_entropy | 685.06 | 51.61 |
| iban | 791.74 | 51.82 |
| ipaddr | 17847.85 | 43.54 |
| jwt | 1065.56 | 27.58 |
| merchant_id | 333.04 | 12.71 |
| mynumber | 548.81 | 48.12 |
| pan | 4717.77 | 41.24 |
| payment_token | 276.62 | 208.34 |
| phone_jp | 32909.97 | 40.50 |
| private_key_pem | 753.46 | 98.44 |
| service_token | 235.68 | 197.97 |
| slack_token | 921.02 | 71.37 |
| swiftbic | 188.83 | 32.41 |
| uk_sortcode | 349.74 | 42.72 |

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
| all | 60,274.000 | 6,487,012.0 | 1.00× / 1.00× |
| kinds1 | 96.955 | 38,425.5 | 621.67× / 168.82× |
| kinds3 | 14,700.500 | 598,465.0 | 4.10× / 10.84× |
| kinds8 | 17,402.000 | 2,790,511.5 | 3.46× / 2.32× |
<!-- narrowing:end -->

The one-kind set is email; three kinds add PAN and credential; eight add Japanese phone, IP address, GitHub token, service token and private-key PEM. Omitting kinds gives up their recall. Select kinds according to the application's output policy and inspect the [real-log false-positive estimates](accuracy.md#public-system-logs).

These dated samples ran ten times with alternating kind order, Go 1.26.11 and GOMAXPROCS=1 on one host. They describe that recorded fixture and implementation, not the current release's universal performance. [Raw samples](performance/scanner-narrowing.raw.txt) retain the variation. Run `make scanner-experiment CPU=8` on an idle Linux machine to refresh the samples; `python3 scripts/scanner_experiment.py --check` only checks the committed table.
