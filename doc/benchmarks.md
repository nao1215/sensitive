# Benchmarks

Run `make benchmark-doc` on an idle machine. It uses Go 1.26.11, GOMAXPROCS=1 and ten 200 ms samples, stores every sample in benchmarks.raw.txt and the medians with machine/source metadata in benchmarks.json, then regenerates the README chart and this page’s tables. Scanner benchmarks cover clean text and each detector's synthetic positive fixture, plus WithAll over all positive fixtures. Mask uses precomputed findings. Recorder includes creation, a writer, an expectation, Check and testing cleanup registration. The slog comparison uses a real JSONHandler and a counting sink, so encoding work is present in both the plain and wrapped measurements.

Shared CI runners have variable load. CI compiles benchmarks and checks the table against its recorded samples; it does not impose a noisy wall-time threshold. Compare base and head manually on the same idle machine and retain both outputs; the round comparison below also alternates runs to reduce time-order bias:

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

The baseline profiles cover WithAll on clean and sensitive inputs and a real masked slog JSON handler. Hint matching repeatedly searched every field, and ASCII numeric detectors allocated identity position maps. Multi-detector scanners now select built-ins through first-byte hint buckets, skip impossible hintless numeric scans, and represent unchanged ASCII positions without a map. SWIFT country strings are allocated only for accepted candidates. Single-detector scanners retain the standard library substring search; the dispatch walk regressed their clean-input latency and was rejected for that case. Inputs scanned by built-ins include a percent-escape check, which adds work to previously minimal single-detector scans. Slog benefits from the same scanner changes; scalar scanning remains intact because numeric scalars can contain PANs and custom detectors may inspect any scalar.

The old hint loop remains a test oracle, compared with the new dispatch on 12,000 generated inputs. A separate byte-domain differential check compares normalization and original positions. Accuracy changes are evaluated separately in the development and held-out corpora.

The new dispatch index is immutable and allocated at scanner construction. Reuse a Scanner across events; constructor-heavy Recorder measurements include this additional setup cost. Built-in percent-encoded scans allocate a decoded buffer and an original-position map; ordinary inputs do not pay that cost.

<!-- comparison:start -->
On the same AMD RYZEN AI MAX+ 395, Linux/amd64 and Go 1.26.11, ten alternating base/head runs used CPU 31, GOMAXPROCS=1 and 300 ms per sample. Base is `610b5f5`; head is `7d54404`, including the review fixes. No intentional CPU workload overlapped these runs. [Raw base](performance/scanner-before.txt), [raw head](performance/scanner-after.txt), and [benchstat output](performance/scanner-benchstat.txt) preserve all observations.

| Operation | Before | After |
|---|---:|---:|
| WithAll clean | 69.240 µs | 33.210 µs |
| WithAll dirty | 5.578 ms | 3.504 ms |
| Masked slog clean | 4.049 µs | 2.025 µs |
| Masked slog dirty | 5.706 µs | 2.889 µs |
| Recorder + Check | 82.731 µs | 62.560 µs |
| Plain slog clean | 865.10 ns | 787.20 ns |
| Plain slog dirty | 786.55 ns | 672.00 ns |

The masked/plain clean-handler ratio changed from 4.68× to 2.57×. Benchstat reports medians with 95% confidence intervals and two-sided tests in the linked output. The following intervals describe the percentage delta, using 20,000 paired bootstrap resamples of the alternating runs, seed 20261115, and the ratio of medians. They are percentile intervals from [benchmark_intervals.py](../scripts/benchmark_intervals.py), distinct from benchstat's individual-median intervals. A delta interval crossing zero does not establish an improvement; variation in the unchanged plain handlers is a control, not a product improvement.

| Benchmark | Time delta | Paired bootstrap 95% interval |
|---|---:|---:|
| Recorder/checked | -24.38% | [-41.88%, +22.77%] |
| Scanner/all/clean | -52.04% | [-69.42%, -17.94%] |
| Scanner/all/dirty | -37.19% | [-45.71%, +25.73%] |
| Slog/masked-clean | -50.00% | [-66.41%, -39.90%] |
| Slog/masked-dirty | -49.36% | [-54.04%, -33.49%] |
| Slog/plain-clean | -9.00% | [-42.15%, +42.66%] |
| Slog/plain-dirty | -14.56% | [-37.38%, +3.90%] |

The clean WithAll and both masked-slog intervals stay below zero. Dirty WithAll and Recorder cross zero, so their timing changes remain inconclusive. The intervals are wide and do not support a precise speedup estimate beyond this workload.

| Operation | B/op before → after | allocs/op before → after |
|---|---:|---:|
| WithAll clean | 52480 → 0 | 131 → 0 |
| WithAll dirty | 2397009 → 996180.5 | 13186 → 12476 |
| Masked slog clean | 864 → 80 | 17 → 5 |
| Masked slog dirty | 1144 → 352 | 24 → 13 |
| Recorder + Check | 35639 → 37335 | 509 → 547 |
| Plain slog clean | 16 → 16 | 1 → 1 |
| Plain slog dirty | 16 → 16 | 1 → 1 |

Recorder allocates 38 more objects (+7.47%) and 4.76% more bytes because each iteration constructs a scanner and its immutable dispatch buckets. This setup tradeoff is included intentionally; reuse scanners across events. Escaped-input buffers are a separate accuracy cost that these unescaped benchmarks do not measure. Empty and custom-only scanners now skip decoding entirely, with a zero-allocation regression test.

A separate alternating ten-sample comparison quantifies the percent-escape check on the fastest single-detector clean paths. These retained regressions provide escaped-value detection; all three cases remain at zero allocations. [Base](performance/single-before.txt), [head](performance/single-after.txt), and [benchstat](performance/single-benchstat.txt) use the same CPU, toolchain and 300 ms protocol.

| Detector | Before | After |
|---|---:|---:|
| email | 59.56 ns | 106.65 ns |
| ipaddr | 105.20 ns | 150.15 ns |
| phone_jp | 110.25 ns | 161.30 ns |

| Benchmark | Time delta | Paired bootstrap 95% interval |
|---|---:|---:|
| Scanner/email/clean | +79.05% | [+78.00%, +91.26%] |
| Scanner/ipaddr/clean | +42.73% | [+41.20%, +44.40%] |
| Scanner/phone_jp/clean | +46.30% | [+42.10%, +48.73%] |

Before/after CPU profiles cover [WithAll clean](performance/before-Scanner-all-clean-profile.txt) / [after](performance/after-Scanner-all-clean-profile.txt), [WithAll dirty](performance/before-Scanner-all-dirty-profile.txt) / [after](performance/after-Scanner-all-dirty-profile.txt), and [masked slog clean](performance/before-Slog-masked-clean-profile.txt) / [after](performance/after-Slog-masked-clean-profile.txt). Hint selection and SWIFT parsing remain clean-input work; GitHub token parsing and context extraction remain sensitive-input work. Selected recognizers still scan individually; detector fusion, buffer pooling and record-wide batching are not implemented.

Run the comparison from the head checkout, with the baseline in `../base9`, starting with empty output files:

```sh
export GOMAXPROCS=1 GOTOOLCHAIN=go1.26.11
for sample in $(seq 1 10); do
  taskset -c 31 go -C ../base9/tests test -run '^$' -bench '^BenchmarkPublished(Scanner|Slog|Recorder)$/^(all|plain-clean|masked-clean|plain-dirty|masked-dirty|checked)$' -benchmem -benchtime=300ms -count=1 . >> base.txt
  taskset -c 31 go -C tests test -run '^$' -bench '^BenchmarkPublished(Scanner|Slog|Recorder)$/^(all|plain-clean|masked-clean|plain-dirty|masked-dirty|checked)$' -benchmem -benchtime=300ms -count=1 . >> head.txt
done
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e base.txt head.txt
python3 scripts/benchmark_intervals.py base.txt head.txt
```

CPU 31 is specific to this machine; select an available CPU on another host. The full publication below uses separate ten 200 ms samples, so its medians differ from this paired comparison.
<!-- comparison:end -->


## Measured results

<!-- benchmarks:start -->
Measured 2026-11-15 with go1.26.11, linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, GOMAXPROCS=1; median of ten 200 ms samples at [da95fde](https://github.com/nao1215/embargo/commit/da95fde8d01b3e3214d70a131aceb07696eedca9).

Background load: no intentional concurrent workload.

| Operation | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Scanner WithAll, clean | 84640.5 | 32.52 | 0 | 0 |
| Scanner WithAll, dirty | 8299013.0 | 4.76 | 1187111 | 14113 |
| Mask | 6343.0 | 464.15 | 13816 | 12 |
| Writer only | 11.5 | 47162.61 | 0 | 0 |
| Recorder + Check | 76290.5 | 7.13 | 40396 | 590 |
| Plain slog, clean | 875.7 | — | 16 | 1 |
| Masked slog, clean | 2573.5 | — | 80 | 5 |
| Plain slog, dirty | 896.4 | — | 16 | 1 |
| Masked slog, dirty | 3503.0 | — | 352 | 13 |

<details>
<summary>Per-detector Scanner throughput</summary>

| Detector | Clean MB/s | Dirty MB/s |
|---|---:|---:|
| aba_routing | 443.04 | 47.84 |
| ach_trace | 594.19 | 5.01 |
| all | 32.52 | 4.76 |
| awskey | 747.04 | 91.90 |
| bank_account | 719.00 | 9.00 |
| btc | 802.57 | 45.16 |
| card_expiry | 1050.50 | 3.58 |
| credential | 85.18 | 37.79 |
| cvv | 371.16 | 4.54 |
| email | 25376.29 | 56.95 |
| eth | 1246.43 | 142.25 |
| github_token | 1129.17 | 125.68 |
| google_api_key | 959.06 | 175.00 |
| high_entropy | 1219.29 | 51.75 |
| iban | 787.13 | 50.66 |
| ipaddr | 17452.50 | 42.64 |
| jwt | 1085.11 | 27.48 |
| merchant_id | 681.92 | 15.79 |
| mynumber | 747.06 | 55.23 |
| pan | 9653.92 | 57.45 |
| payment_token | 171.72 | 117.73 |
| phone_jp | 31310.58 | 39.88 |
| private_key_pem | 782.56 | 99.37 |
| service_token | 239.24 | 203.36 |
| slack_token | 956.59 | 70.90 |
| swiftbic | 159.53 | 34.18 |
| uk_sortcode | 444.26 | 43.47 |

</details>
<!-- benchmarks:end -->

## Round 12 cost of discovering forgotten credentials

[Paired raw results and benchstat](performance/round12-benchstat.txt) compare main 9c9d3cf with da95fde on CPU 8, Go 1.26.11, GOMAXPROCS=1, ten 200 ms samples per case, alternating the baseline/head order each pair. [Metadata](performance/round12-metadata.json) records the exact command and commits. The earlier unpinned exploratory run also slowed plain slog by roughly 20%, so it was not used to attribute a code regression.

IP and Japanese-phone clean scans are statistically unchanged (155.6→154.9 ns and 159.1→161.2 ns). Email measures 110.3→106.8 ns (-3.13%); this small measured difference does not establish a dispatch optimization, especially given the plain-handler control drift below. This round does not recover the 45–51 ns added by round 9's percent-decoding scan. Removing that pass would break the encoded-value detection contract; no speculative fast path was shipped.

All-detector clean scans increase from 47.33 to 85.35 µs (+80.32%) because the default set now parses credential assignments and URL/DSN syntax and scans unprefixed entropy candidates. Common-key normalization uses stack storage to reduce the new parser's cost. Clean masked slog increases 2.332→2.560 µs (+9.78%) and dirty masked slog 3.312→3.519 µs (+6.25%); plain slog also changes +4.27%/+4.16%, showing residual environmental noise. The paired cases retain the same allocations. Explicit WithKinds avoids the cost of detectors the caller does not need.

The published all-detector dirty corpus now includes the three new families, so its throughput is not an identical-work comparison with round 11. The paired clean comparison above keeps the input unchanged and exposes the default-policy cost. The generated table includes individual clean/dirty measurements for all 26 detectors.

The full-matrix publication is a snapshot, not a paired regression estimate. Some unchanged cases differ substantially from narrow runs: Japanese-phone clean input is about 87.9 ns in the full matrix versus 161.2 ns in the paired run. The input and source are unchanged, so these observations do not establish a code improvement. Retain the raw samples and use the alternating comparisons above to assess this round; further isolation is needed to explain the matrix-dependent timing variation.
