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

## Profiles and the expiry change

The original card-expiry dirty profile spent 73.63% of sampled CPU time in `reportedDateAt`, checking previously reported spans at every byte. The revised loop parses a date candidate before probing that map, and constructs month/year strings only for accepted candidates. Existing overlap, format, property and corpus tests retain the behavior.

On the same pinned CPU, five 300 ms samples changed the expiry median from 919.8 µs to 221.3 µs and the all-detector dirty median from 7.679 ms to 6.354 ms. Allocations were unchanged. These are sample medians: five samples do not provide benchstat's 95% confidence interval.

[Before samples](performance/expiry-before.txt), [after samples](performance/expiry-after.txt), [benchstat](performance/expiry-benchstat.txt), and the [expiry profile](performance/expiry-profile.txt) preserve the evidence. They are a separate comparison from the full 200 ms publication below.

The [all-detector profile](performance/all-profile.txt) still attributes 17.51% of sampled CPU time to expiry search. The [clean masked-slog profile](performance/slog-profile.txt) attributes 71.63% to scanning, including 41.60% to repeated hint matching. Reducing repeated scans across attributes remains a performance task; changing detector hints needs separate equivalence tests.

## Measured results

<!-- benchmarks:start -->
Measured 2026-11-15 with go1.26.11, linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, GOMAXPROCS=1; median of five 200 ms samples at [6eed0a6](https://github.com/nao1215/embargo/commit/6eed0a6d1c02ddd98984a8f750ebba14eefdb1b9).

Background load: no intentional concurrent workload.

| Operation | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Scanner WithAll, clean | 48769.0 | 56.43 | 52480 | 131 |
| Scanner WithAll, dirty | 3344245.0 | 9.89 | 2397010 | 13186 |
| Mask | 3359.0 | 876.55 | 13816 | 12 |
| Writer only | 7.0 | 77416.20 | 0 | 0 |
| Recorder + Check | 51074.0 | 10.65 | 35640 | 509 |
| Plain slog, clean | 496.5 | — | 16 | 1 |
| Masked slog, clean | 3892.0 | — | 864 | 17 |
| Plain slog, dirty | 622.0 | — | 16 | 1 |
| Masked slog, dirty | 5763.0 | — | 1144 | 24 |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 284.44 | 46.27 |
| ach_trace | 637.14 | 5.03 |
| all | 56.43 | 9.89 |
| awskey | 771.68 | 180.42 |
| bank_account | 539.67 | 8.88 |
| btc | 1410.22 | 83.24 |
| card_expiry | 1939.09 | 6.05 |
| cvv | 686.09 | 6.30 |
| email | 45384.28 | 60.30 |
| eth | 1328.89 | 142.38 |
| github_token | 1184.25 | 131.53 |
| google_api_key | 959.13 | 183.99 |
| iban | 809.72 | 53.78 |
| ipaddr | 26264.08 | 83.46 |
| jwt | 2240.06 | 51.41 |
| merchant_id | 611.90 | 21.00 |
| mynumber | 441.20 | 86.41 |
| pan | 5506.73 | 42.99 |
| payment_token | 142.05 | 133.78 |
| phone_jp | 24948.09 | 43.27 |
| private_key_pem | 1467.90 | 107.20 |
| slack_token | 1895.25 | 97.82 |
| swiftbic | 284.77 | 59.54 |
| uk_sortcode | 674.09 | 82.08 |

</details>
<!-- benchmarks:end -->
