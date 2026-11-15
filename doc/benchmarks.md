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
Measured 2026-11-15 with go1.26.11, linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, GOMAXPROCS=1; median of five 200 ms samples at [87191b9](https://github.com/nao1215/embargo/commit/87191b97decbdee972eb94e8bad7fe9eb135f55a).

Background load: no intentional concurrent workload.

| Operation | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Scanner WithAll, clean | 95501.0 | 28.82 | 52480 | 131 |
| Scanner WithAll, dirty | 6375692.0 | 5.19 | 2397010 | 13186 |
| Mask | 5446.0 | 540.60 | 13816 | 12 |
| Writer only | 11.3 | 47975.29 | 0 | 0 |
| Recorder + Check | 82141.0 | 6.62 | 35636 | 509 |
| Plain slog, clean | 883.3 | — | 16 | 1 |
| Masked slog, clean | 4920.0 | — | 864 | 17 |
| Plain slog, dirty | 856.2 | — | 16 | 1 |
| Masked slog, dirty | 5687.0 | — | 1144 | 24 |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 516.53 | 50.46 |
| ach_trace | 639.39 | 4.87 |
| all | 28.82 | 5.19 |
| awskey | 773.06 | 99.54 |
| bank_account | 591.37 | 5.72 |
| btc | 1427.58 | 87.87 |
| card_expiry | 964.85 | 4.86 |
| cvv | 737.91 | 5.83 |
| email | 85442.57 | 109.50 |
| eth | 2581.14 | 205.20 |
| github_token | 1008.60 | 165.18 |
| google_api_key | 1831.24 | 110.69 |
| iban | 400.18 | 91.00 |
| ipaddr | 49273.61 | 59.70 |
| jwt | 1435.07 | 53.68 |
| merchant_id | 617.77 | 22.81 |
| mynumber | 458.81 | 93.15 |
| pan | 9173.05 | 43.18 |
| payment_token | 141.47 | 131.26 |
| phone_jp | 25201.24 | 43.52 |
| private_key_pem | 774.86 | 113.84 |
| slack_token | 954.71 | 73.51 |
| swiftbic | 182.56 | 34.92 |
| uk_sortcode | 370.66 | 44.74 |

</details>
<!-- benchmarks:end -->
