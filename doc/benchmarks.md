# Benchmarks

Run `make benchmark-doc` on an idle machine. It uses Go 1.26.11, GOMAXPROCS=1 and five 200 ms samples, stores every sample in benchmarks.raw.txt and the medians with machine/source metadata in benchmarks.json, then regenerates the README chart and this page’s tables. Scanner benchmarks cover clean text and each detector's synthetic positive fixture, plus WithAll over all positive fixtures. Mask uses precomputed findings. Recorder includes creation, a writer, an expectation, Check and testing cleanup registration. The slog comparison uses a real JSONHandler and a counting sink, so encoding work is present in both the plain and wrapped measurements.

Shared CI runners have variable load. CI compiles benchmarks and checks the table against its recorded samples; it does not impose a noisy wall-time threshold. Compare base and head manually on the same idle machine, alternating the runs and retaining both outputs:

```sh
git worktree add ../embargo-benchmark-base "$(git merge-base HEAD origin/main)"
GOMAXPROCS=1 GOTOOLCHAIN=go1.26.11 go -C ../embargo-benchmark-base/tests test -run '^$' -bench '^BenchmarkPublished' -benchmem -count=10 . > base.txt
GOMAXPROCS=1 GOTOOLCHAIN=go1.26.11 go -C tests test -run '^$' -bench '^BenchmarkPublished' -benchmem -count=10 . > head.txt
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e base.txt head.txt
```

Use a base that contains these benchmark names and a compatible API. The first benchmark publication has no comparable base for the newly introduced recorder and slog wrapper. Keep timing differences separate from allocations and throughput, and inspect confidence intervals before drawing conclusions.

## Measured results

<!-- benchmarks:start -->
Measured 2026-11-15 with go1.26.11, linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, GOMAXPROCS=1; median of five 200 ms samples at [4174a6a](https://github.com/nao1215/embargo/commit/4174a6a59e5bffcaacaf5212432846873cbc6e4c).

Background load: no intentional concurrent workload.

| Operation | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Scanner WithAll, clean | 95437.0 | 28.84 | 52480 | 131 |
| Scanner WithAll, dirty | 7532386.0 | 4.39 | 2397010 | 13186 |
| Mask | 6009.0 | 489.91 | 13816 | 12 |
| Writer only | 11.3 | 48196.88 | 0 | 0 |
| Recorder + Check | 80178.0 | 6.78 | 35637 | 509 |
| Plain slog, clean | 817.4 | — | 16 | 1 |
| Masked slog, clean | 4954.0 | — | 864 | 17 |
| Plain slog, dirty | 808.0 | — | 16 | 1 |
| Masked slog, dirty | 5740.0 | — | 1144 | 24 |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 496.03 | 35.43 |
| ach_trace | 928.27 | 9.12 |
| all | 28.84 | 4.39 |
| awskey | 1086.78 | 170.21 |
| bank_account | 1117.73 | 10.92 |
| btc | 1380.38 | 90.61 |
| card_expiry | 1312.22 | 0.74 |
| cvv | 520.48 | 5.19 |
| email | 70963.90 | 64.75 |
| eth | 1017.77 | 170.58 |
| github_token | 1699.29 | 246.58 |
| google_api_key | 1823.65 | 334.91 |
| iban | 1461.30 | 98.12 |
| ipaddr | 47223.18 | 45.84 |
| jwt | 1133.57 | 29.21 |
| merchant_id | 340.50 | 13.01 |
| mynumber | 251.85 | 51.64 |
| pan | 5025.22 | 42.81 |
| payment_token | 142.66 | 132.59 |
| phone_jp | 25268.77 | 43.71 |
| private_key_pem | 791.94 | 116.08 |
| slack_token | 1171.15 | 76.15 |
| swiftbic | 182.09 | 35.57 |
| uk_sortcode | 358.23 | 45.08 |

</details>
<!-- benchmarks:end -->
