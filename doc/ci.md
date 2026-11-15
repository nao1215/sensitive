# CI timing and execution policy

Round 14 compares PR #81 head `5ae14696d60444869b7020aa62814bbcb63fb15a` with PR #83 implementation head `aee3d602148152ca8270c3caa526e2fdff7e227c`. Workflow time is creation to the final job completion, including queue and dependencies; job time is started_at to completed_at. Raw GitHub timestamps are collected with gh run list and the Actions jobs API. The [base timestamps](performance/round14-ci-base.json) and [head timestamps](performance/round14-ci-head.json) retain every job and step. All nine head workflows succeeded. The earlier 2129aa3 lockfile startup failures ran zero jobs and are excluded from this comparison. Later evidence-only edits are checked again before merge; the table identifies the measured implementation commit.

| Workflow | Base seconds | Head seconds |
|---|---:|---:|
| Coverage | 84 | 88 |
| golangci-lint | 128 | 68 |
| MultiPlatformUnitTest | 134 | 156 |
| reviewdog | 27 | 51 |
| govulncheck | 50 | 53 |
| Trivy | 25 | 24 |
| Gosec | 72 | 74 |
| CodeQL | 68 | 71 |
| Verification | Added | 72 |

| Job | Base seconds | Head seconds |
|---|---:|---:|
| Coverage: changes / changes | 3 | 3 |
| Coverage: Unit test (linux) (ubuntu-latest) | 75 | 80 |
| golangci-lint: changes / changes | 5 | 9 |
| golangci-lint: golangci-lint (tests module) | 20 | 25 |
| golangci-lint: golangci-lint | 118 | 48 |
| golangci-lint: golangci-lint (adapters) | 39 | 30 |
| MultiPlatformUnitTest: README and runnable Examples | 27 | 15 |
| MultiPlatformUnitTest: changes / changes | 5 | 5 |
| MultiPlatformUnitTest: Cross build (netbsd) | 17 | 24 |
| MultiPlatformUnitTest: Property tests (macos-latest, Go stable) | 74 | 98 |
| MultiPlatformUnitTest: Property tests (macos-latest, Go 1.26.11) | 75 | 52 |
| MultiPlatformUnitTest: Property tests (windows-latest, Go 1.26.11) | 59 | 64 |
| MultiPlatformUnitTest: Cross build (freebsd) | 28 | 33 |
| MultiPlatformUnitTest: Property tests (ubuntu-latest, Go 1.26.11) | 28 | 22 |
| MultiPlatformUnitTest: Property tests (ubuntu-latest, Go stable) | 24 | 76 |
| MultiPlatformUnitTest: Cross build (openbsd) | 32 | 23 |
| MultiPlatformUnitTest: Property tests (windows-latest, Go stable) | 58 | 145 |
| MultiPlatformUnitTest: Unit test (ubuntu-latest, stable) | 54 | 72 |
| MultiPlatformUnitTest: Unit test (macos-latest, stable) | 47 | 100 |
| MultiPlatformUnitTest: Unit test (macos-latest, 1.26.11) | 104 | 53 |
| MultiPlatformUnitTest: Unit test (windows-latest, 1.26.11) | 123 | 59 |
| MultiPlatformUnitTest: Unit test (ubuntu-latest, 1.26.11) | 44 | 26 |
| MultiPlatformUnitTest: Unit test (windows-latest, stable) | 82 | 114 |
| reviewdog: changes / changes | 3 | 4 |
| reviewdog: misspell | 10 | 15 |
| reviewdog: golangci-lint | 18 | 41 |
| reviewdog: actionlint | 7 | 10 |
| govulncheck: changes / changes | 3 | 5 |
| govulncheck: govulncheck (., Go 1.26.11) | 35 | 41 |
| govulncheck: govulncheck (adapters/zerolog, Go 1.26.11) | 32 | 43 |
| govulncheck: govulncheck (., Go stable) | 35 | 34 |
| govulncheck: govulncheck (adapters/logrus, Go stable) | 32 | 37 |
| govulncheck: govulncheck (tests, Go 1.26) | 35 | 39 |
| govulncheck: govulncheck (adapters/zerolog, Go stable) | 28 | 36 |
| govulncheck: govulncheck (adapters/zap, Go stable) | 35 | 32 |
| govulncheck: govulncheck (adapters/zap, Go 1.26.11) | 40 | 43 |
| govulncheck: govulncheck (adapters/logrus, Go 1.26.11) | 40 | 33 |
| govulncheck: govulncheck (tests, Go stable) | 39 | 36 |
| Trivy: scan | 22 | 21 |
| Gosec: scan (adapters/logrus) | 27 | 35 |
| Gosec: scan (.) | 69 | 71 |
| Gosec: scan (tests) | 57 | 57 |
| Gosec: scan (adapters/zerolog) | 28 | 31 |
| Gosec: scan (adapters/zap) | 30 | 28 |
| CodeQL: Analyze (go) | 65 | 68 |
| Verification: policies | Added | 16 |
| Verification: changes / changes | Added | 4 |
| Verification: formal | Added | 62 |
| Verification: benchmark | Added | 41 |

The slowest baseline jobs were the Windows minimum-Go unit leg (123 seconds), enforced root lint (118 seconds) and macOS minimum-Go unit leg (104 seconds). Root lint spent 34 seconds resolving/running architecture checks and 66 seconds in the negative-fixture step, which installed golangci-lint again after its action had already installed the same version and added it to PATH. Round 14 reuses that binary. The six unit legs previously produced unused coverage profiles; Coverage retains the instrumented root and integration runs and the 97% gate, while the OS matrix executes the tests without redundant instrumentation.

Head root lint fell from 118 to 48 seconds; the negative-fixture step fell from 66 to 10 seconds after binary reuse, while architecture checks fell from 34 to 22 seconds. The slowest head job was Windows stable property/race testing at 145 seconds: setup-go took 40 seconds despite an 84 MB cache hit, including about 15 seconds extracting the cache, and the test step took 87 seconds. The test binary reported 40.938 seconds for the main tests package; compilation, dependency preparation and other packages account for the rest. Added race coverage costs time, so the unit workflow rose from 134 to 156 seconds. Reviewdog also rose from 27 to 51 seconds, with 36 seconds in its lint annotation step; this observation is retained without attributing all variation to code changes.

Minimum and stable Go remain on Linux, Windows and macOS. Stable legs run the race detector for the root, tests and adapter modules; minimum-Go legs retain ordinary tests. Adapter race coverage remains on all three OSes without repeating it in both toolchain legs. Documentation-only changes continue to skip code jobs while documentation and policy checks run. Formal verification and paired benchmarks use the same change classification; heavy mutation and scaling run weekly, and fuzz search runs nightly. Shared runners and cache state affect the timing table, so an observed delta is not attributed solely to one edit.

CodeRabbit is configured to review the Lean and Quint source, generators and replay assertions; regenerated vector and trace bulk is excluded from prose review while formal CI checks exact staleness. Intentional output snapshots remain reviewable. Verification costs 72 seconds wall time with separate runner jobs: policies 16 seconds, formal 62 seconds and paired benchmark 41 seconds. Quint generation/model checking took 25 seconds, Lean download/extraction 14 seconds and compilation/vector checks 8 seconds. Model/oracle replay in policies took 6 seconds, lock provenance checking 2 seconds and prose checking 1 second; API timestamps round subsecond checks to zero. Metamorphic and snapshot assertions share the ordinary/race jobs, so these runs do not isolate their marginal cost. Mutation and scaling remain weekly, with no claimed GitHub duration before a scheduled run; their local measured costs are recorded in testing.md. Each future round report must retain a workflow/job timing table, commit IDs, slowest-job causes and the effect of any CI edit. Do not omit a check merely to improve the table.

## Paired benchmark observation

[Run 43769588959](https://github.com/nao1215/embargo/actions/runs/43769588959) compared base 83e325c with head aee3d60 on one Intel Xeon Platinum 8573C runner using Go 1.26.11 and GOMAXPROCS=1. Each binary ran ten 100ms samples in alternating order; the [conditions](performance/round14-paired-conditions.json), [base samples](performance/round14-paired-base.txt), [head samples](performance/round14-paired-head.txt) and [benchstat output](performance/round14-paired-benchstat.txt) retain the evidence. The time geomean changed by +0.63%; the statistically distinguishable changes were all/clean -1.02%, kinds3/clean +6.63% and kinds8/clean +2.17%. Allocation counts matched in every case. These are runner observations, including regressions, without a wall-time gate or a claim about the cause of small deltas.

[Support maintenance](https://github.com/sponsors/nao1215).
