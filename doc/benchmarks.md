# Benchmarks

Run `make benchmark-doc` on an idle machine. It uses Go 1.26.11, GOMAXPROCS=1 and ten 200 ms samples, stores every sample in benchmarks.raw.txt and the medians with machine/source metadata in benchmarks.json, then regenerates the README chart and this page’s tables. Scanner benchmarks cover clean text and each detector's synthetic positive fixture, plus WithAll over all positive fixtures. Mask uses precomputed findings. Recorder includes creation, a writer, an expectation, Check and testing cleanup registration. The slog comparison uses a real JSONHandler and a counting sink, so encoding work is present in both the plain and wrapped measurements.

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

## Scanner dispatch and allocation changes

The baseline profiles cover WithAll on clean and sensitive inputs and a real masked slog JSON handler. Hint matching repeatedly searched every field, and ASCII numeric detectors allocated identity position maps. Multi-detector scanners now select built-ins through first-byte hint buckets, skip impossible hintless numeric scans, and represent unchanged ASCII positions without a map. SWIFT country strings are allocated only for accepted candidates. Single-detector scanners retain the standard library substring search; the dispatch walk regressed their clean-input latency and was rejected for that case. All inputs now include a percent-escape check, which adds work to previously minimal single-detector scans. Slog benefits from the same scanner changes; scalar scanning remains intact because numeric scalars can contain PANs and custom detectors may inspect any scalar.

The old hint loop remains a test oracle, compared with the new dispatch on 12,000 generated inputs. A separate byte-domain differential check compares normalization and original positions. Accuracy changes are evaluated separately in the development and held-out corpora.

The new dispatch index is immutable and allocated at scanner construction. Reuse a Scanner across events; constructor-heavy Recorder measurements include this additional setup cost. Percent-encoded inputs allocate a decoded buffer and an original-position map; ordinary inputs do not pay that cost.

<!-- comparison:start -->
On the same AMD RYZEN AI MAX+ 395, Linux/amd64 and Go 1.26.11, ten alternating base/head runs used CPU 31, GOMAXPROCS=1 and 300 ms per sample. Base is `610b5f5`; head executable changes are `3a28f60`. No intentional CPU workload overlapped these runs. [Raw base](performance/scanner-before.txt), [raw head](performance/scanner-after.txt), and [benchstat output](performance/scanner-benchstat.txt) preserve all observations.

WithAll clean time fell from 94.75 µs to 47.89 µs (-49.46%); masked slog clean time fell from 4.969 µs to 2.226 µs (-55.21%). The masked/plain clean ratio fell from 5.53× to 2.53×. Masked slog dirty time fell from 5.676 µs to 3.076 µs (-45.82%). WithAll dirty time changed from 6.277 ms to 6.018 ms (-4.12%), but neither its benchstat comparison (p=0.063) nor its delta interval establishes a speed improvement. Recorder's time change is also inconclusive. The plain dirty handler has a small benchstat p-value but its paired interval crosses zero; do not attribute that control variation to this change.

Benchstat reports medians with 95% confidence intervals and two-sided tests in the linked output. The following intervals describe the percentage delta, using 20,000 paired bootstrap resamples of the alternating runs, seed 20261115, and the ratio of medians. They are percentile intervals, calculated by [benchmark_intervals.py](../scripts/benchmark_intervals.py); they are distinct from benchstat's individual-median intervals.

| Benchmark | Time delta | Paired bootstrap 95% interval |
|---|---:|---:|
| Recorder/checked | -6.01% | [-8.83%, +5.89%] |
| Scanner/all/clean | -49.46% | [-50.17%, -48.51%] |
| Scanner/all/dirty | -4.12% | [-7.68%, +20.17%] |
| Slog/masked-clean | -55.21% | [-56.75%, -54.19%] |
| Slog/masked-dirty | -45.82% | [-57.37%, -33.16%] |
| Slog/plain-clean | -2.30% | [-7.77%, +0.91%] |
| Slog/plain-dirty | -4.64% | [-32.64%, +1.21%] |

| Operation | B/op before → after | allocs/op before → after |
|---|---:|---:|
| WithAll clean | 52480 → 0 | 131 → 0 |
| WithAll dirty | 2397009 → 996181 | 13186 → 12476 |
| Masked slog clean | 864 → 80 | 17 → 5 |
| Masked slog dirty | 1144 → 352 | 24 → 13 |
| Recorder + Check | 35638.5 → 37332.5 | 509 → 547 |

Recorder allocates 38 more objects (+7.47%) and 4.75% more bytes because each iteration constructs a scanner and its immutable dispatch buckets. This is a setup tradeoff for reused scanners; the benchmark intentionally includes it. Scanner and slog scanning allocations decreased. Escaped-input buffers remain a separate accuracy cost that these unescaped benchmarks do not measure.

A separate alternating ten-sample comparison of the fastest single-detector clean paths quantifies the percent-escape check: email changes from 60.22 ns to 103.95 ns, IP address from 106.5 ns to 148.6 ns, and Japanese phone from 110.8 ns to 151.9 ns. This is a real regression of about 41–44 ns per scan, retained to detect escaped values; all three remain at zero allocations. [Base samples](performance/single-before.txt), [head samples](performance/single-after.txt), and [benchstat](performance/single-benchstat.txt) use the same CPU, toolchain and 300 ms protocol.

| Benchmark | Time delta | Paired bootstrap 95% interval |
|---|---:|---:|
| Scanner/email/clean | +72.60% | [+67.93%, +73.99%] |
| Scanner/ipaddr/clean | +39.55% | [+36.43%, +41.55%] |
| Scanner/phone_jp/clean | +37.05% | [+35.44%, +38.16%] |

The before/after CPU profiles cover [WithAll clean](performance/before-Scanner-all-clean-profile.txt) / [after](performance/after-Scanner-all-clean-profile.txt), [WithAll dirty](performance/before-Scanner-all-dirty-profile.txt) / [after](performance/after-Scanner-all-dirty-profile.txt), and [masked slog clean](performance/before-Slog-masked-clean-profile.txt) / [after](performance/after-Slog-masked-clean-profile.txt). After the change, clean scanning spends 39.65% cumulative CPU in detector selection and 28.28% in SWIFT parsing. Dirty scanning still spends 17.28% in GitHub token parsing and 12.60% in context extraction. Selected recognizers still walk the input individually; detector fusion, buffer pooling and record-wide batching are not implemented.

The comparison commands, run from the head checkout with the baseline in `../base9`, are:

```sh
export GOMAXPROCS=1 GOTOOLCHAIN=go1.26.11
for sample in $(seq 1 10); do
  taskset -c 31 go -C ../base9/tests test -run '^$' -bench '^BenchmarkPublished(Scanner|Slog|Recorder)$/^(all|plain-clean|masked-clean|plain-dirty|masked-dirty|checked)$' -benchmem -benchtime=300ms -count=1 . >> base.txt
  taskset -c 31 go -C tests test -run '^$' -bench '^BenchmarkPublished(Scanner|Slog|Recorder)$/^(all|plain-clean|masked-clean|plain-dirty|masked-dirty|checked)$' -benchmem -benchtime=300ms -count=1 . >> head.txt
done
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e base.txt head.txt
python3 scripts/benchmark_intervals.py base.txt head.txt
```

Start with empty output files. CPU 31 is specific to this machine; select one available CPU on another host. The full publication below uses separate ten 200 ms samples, so its medians differ from this paired comparison.
<!-- comparison:end -->


## Measured results

<!-- benchmarks:start -->
Measured 2026-11-15 with go1.26.11, linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, GOMAXPROCS=1; median of ten 200 ms samples at [3a28f60](https://github.com/nao1215/embargo/commit/3a28f60c650c7e1cb7d29d0dc9987804965db6da).

Background load: no intentional concurrent workload.

| Operation | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Scanner WithAll, clean | 48407.0 | 56.85 | 0 | 0 |
| Scanner WithAll, dirty | 6032112.0 | 5.48 | 996181 | 12476 |
| Mask | 6072.5 | 484.80 | 13816 | 12 |
| Writer only | 11.4 | 47821.73 | 0 | 0 |
| Recorder + Check | 72679.5 | 7.52 | 37330 | 547 |
| Plain slog, clean | 649.9 | — | 16 | 1 |
| Masked slog, clean | 1236.0 | — | 80 | 5 |
| Plain slog, dirty | 511.8 | — | 16 | 1 |
| Masked slog, dirty | 3104.0 | — | 352 | 13 |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 449.05 | 50.34 |
| ach_trace | 872.00 | 5.92 |
| all | 56.85 | 5.48 |
| awskey | 1378.28 | 160.49 |
| bank_account | 878.65 | 5.46 |
| btc | 826.11 | 46.47 |
| card_expiry | 1069.86 | 5.93 |
| cvv | 678.31 | 4.38 |
| email | 27694.65 | 61.66 |
| eth | 1301.84 | 140.86 |
| github_token | 1261.20 | 219.08 |
| google_api_key | 1462.45 | 334.22 |
| iban | 1545.83 | 103.25 |
| ipaddr | 34464.65 | 79.10 |
| jwt | 1734.62 | 28.88 |
| merchant_id | 338.34 | 12.17 |
| mynumber | 429.78 | 52.20 |
| pan | 4763.52 | 41.44 |
| payment_token | 141.72 | 131.16 |
| phone_jp | 18482.71 | 70.78 |
| private_key_pem | 784.01 | 114.35 |
| slack_token | 974.36 | 74.09 |
| swiftbic | 186.06 | 35.38 |
| uk_sortcode | 368.52 | 44.59 |

</details>
<!-- benchmarks:end -->
