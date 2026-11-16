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

## Round 15 PR A timings

The base is main d369f0934571b30901f9a4ec4dd4c26db1f65d2a; head is PR #86 implementation 5468cb0895bc4235ab334687c88fbff846113c23. [Base timestamps](performance/round15-a-ci-base.json) and [head timestamps](performance/round15-a-ci-head.json) retain every workflow, job and step. Workflow time includes queueing. Reviewdog has no main-push baseline; its round-14 PR comparison is given separately. Scorecard runs on main rather than this pull request.

| Workflow | Base seconds | Head seconds |
|---|---:|---:|
| CodeQL | 68 | 62 |
| Coverage | 115 | 82 |
| Gosec | 83 | 90 |
| MultiPlatformUnitTest | 355 | 154 |
| Scorecard | 65 | n/a |
| Trivy | 46 | 30 |
| Verification | 86 | 81 |
| golangci-lint | 105 | 91 |
| govulncheck | 93 | 65 |
| reviewdog | n/a | 47 |

| Job | Base seconds | Head seconds |
|---|---:|---:|
| CodeQL: Analyze (go) | 65 | 59 |
| Coverage: Unit test (linux) (ubuntu-latest) | 82 | 72 |
| Coverage: changes / changes | 5 | 5 |
| Gosec: scan (.) | 58 | 87 |
| Gosec: scan (adapters/logrus) | 27 | 30 |
| Gosec: scan (adapters/zap) | 30 | 32 |
| Gosec: scan (adapters/zerolog) | 31 | 27 |
| Gosec: scan (tests) | 45 | 61 |
| MultiPlatformUnitTest: Cross build (freebsd) | 23 | 28 |
| MultiPlatformUnitTest: Cross build (netbsd) | 23 | 21 |
| MultiPlatformUnitTest: Cross build (openbsd) | 26 | 30 |
| MultiPlatformUnitTest: Property tests (macos-latest, Go 1.26.11) | 52 | 41 |
| MultiPlatformUnitTest: Property tests (macos-latest, Go stable) | 103 | 115 |
| MultiPlatformUnitTest: Property tests (ubuntu-latest, Go 1.26.11) | 30 | 25 |
| MultiPlatformUnitTest: Property tests (ubuntu-latest, Go stable) | 95 | 78 |
| MultiPlatformUnitTest: Property tests (windows-latest, Go 1.26.11) | 71 | 72 |
| MultiPlatformUnitTest: Property tests (windows-latest, Go stable) | 117 | 142 |
| MultiPlatformUnitTest: README and runnable Examples | 14 | 17 |
| MultiPlatformUnitTest: Unit test (macos-latest, 1.26.11) | 49 | 73 |
| MultiPlatformUnitTest: Unit test (macos-latest, stable) | 101 | 91 |
| MultiPlatformUnitTest: Unit test (ubuntu-latest, 1.26.11) | 29 | 36 |
| MultiPlatformUnitTest: Unit test (ubuntu-latest, stable) | 90 | 79 |
| MultiPlatformUnitTest: Unit test (windows-latest, 1.26.11) | 92 | 86 |
| MultiPlatformUnitTest: Unit test (windows-latest, stable) | 135 | 141 |
| MultiPlatformUnitTest: changes / changes | 6 | 5 |
| Scorecard: Scorecard analysis | 39 | n/a |
| Trivy: scan | 25 | 27 |
| Verification: benchmark | 0 | 41 |
| Verification: changes / changes | 6 | 5 |
| Verification: formal | 63 | 68 |
| Verification: policies | 19 | 15 |
| golangci-lint: changes / changes | 6 | 7 |
| golangci-lint: golangci-lint | 72 | 77 |
| golangci-lint: golangci-lint (adapters) | 40 | 31 |
| golangci-lint: golangci-lint (tests module) | 18 | 22 |
| govulncheck: changes / changes | 4 | 7 |
| govulncheck: govulncheck (., Go 1.26.11) | 37 | 43 |
| govulncheck: govulncheck (., Go stable) | 32 | 40 |
| govulncheck: govulncheck (adapters/logrus, Go 1.26.11) | 33 | 52 |
| govulncheck: govulncheck (adapters/logrus, Go stable) | 29 | 36 |
| govulncheck: govulncheck (adapters/zap, Go 1.26.11) | 42 | 34 |
| govulncheck: govulncheck (adapters/zap, Go stable) | 27 | 34 |
| govulncheck: govulncheck (adapters/zerolog, Go 1.26.11) | 32 | 30 |
| govulncheck: govulncheck (adapters/zerolog, Go stable) | 33 | 30 |
| govulncheck: govulncheck (tests, Go 1.26) | 40 | 36 |
| govulncheck: govulncheck (tests, Go stable) | 29 | 35 |
| reviewdog: actionlint | n/a | 9 |
| reviewdog: changes / changes | n/a | 6 |
| reviewdog: golangci-lint | n/a | 35 |
| reviewdog: misspell | n/a | 10 |

The baseline unit workflow took 355 seconds, although its longest job ran for 135 seconds; queueing and dependency scheduling dominate that workflow delta. Head took 154 seconds with a 142-second Windows stable property job. Relative to the earlier round-14 observation, the unit workflow changed from 156 to 154 seconds and reviewdog from 51 to 47 seconds. These small differences do not establish a speedup on shared runners. The local property race suite, including the new severity evaluation in both measurements, changed from 36.33 to 29.81 seconds after reusing immutable per-kind scanners; each value is one run.

The round-14 reviewdog log shows a cache miss under a key derived from an absent root go.sum and about 31 seconds of analysis. The new cache key includes Go/linter versions, source and configuration, with a restore prefix for previous analysis. The first head lint job took 35 seconds, including a 27-second action step; a cold cache still has to be populated. Go and golangci-lint are pinned to the same versions used by the enforced gate. No linter, OS, toolchain, race leg or security check was removed.

In run 43771109571 attempt 1, macOS job 132987100957 passed setup-go and local adapter tests, then failed to verify embargo v0.4.0 because sum.golang.org hit a TLS handshake timeout. Optional-module cache keys now include adapters/*/go.sum. A separate module-download step makes at most three attempts with one- and two-second backoffs; test execution itself is never retried. Published dependency verification still removes local replacements and checks the real declared root module.

The Quint release-download installer from PR #85 remains in the formal job immediately after npm ci. Its version check runs before the cached executable is accepted. Python tests exercise a mismatched expected version with an existing cached executable and check the workflow ordering; a tests/models npm bump is classified as code and must pass the formal job.

## Round 15 production-hook CI

PR B compares main 780b634915d21ff1782ecd5cde6e1956fb10f949 with implementation head 63f0b3161ca0f82df3914f1310ae79755224b592. The [base observations](performance/round15-b-ci-base.json) and [head observations](performance/round15-b-ci-head.json) retain workflow and job timestamps. Seconds are rounded elapsed wall time; workflow duration includes scheduling. n/a means the workflow did not run for that event, or the skipped job has no valid duration. These records pin this measured code revision; the PR and round report retain the final documentation head's times separately.

| Workflow | Base seconds | Head seconds |
|---|---:|---:|
| CodeQL | 79 | 81 |
| Coverage | 106 | 114 |
| Gosec | 67 | 73 |
| MultiPlatformUnitTest | 194 | 179 |
| Scorecard | 32 | n/a |
| Trivy | 25 | 36 |
| Verification | 88 | 81 |
| golangci-lint | 89 | 94 |
| govulncheck | 57 | 54 |
| reviewdog | n/a | 31 |

| Job | Base seconds | Head seconds |
|---|---:|---:|
| CodeQL: Analyze (go) | 75 | 77 |
| Coverage: Unit test (linux) (ubuntu-latest) | 79 | 103 |
| Coverage: changes / changes | 11 | 5 |
| Gosec: scan (.) | 59 | 70 |
| Gosec: scan (adapters/grpc) | n/a | 34 |
| Gosec: scan (adapters/logrus) | 30 | 29 |
| Gosec: scan (adapters/otel) | n/a | 33 |
| Gosec: scan (adapters/sentry) | n/a | 26 |
| Gosec: scan (adapters/zap) | 25 | 28 |
| Gosec: scan (adapters/zerolog) | 24 | 29 |
| Gosec: scan (tests) | 62 | 52 |
| MultiPlatformUnitTest: Cross build (freebsd) | 31 | 21 |
| MultiPlatformUnitTest: Cross build (netbsd) | 14 | 20 |
| MultiPlatformUnitTest: Cross build (openbsd) | 22 | 26 |
| MultiPlatformUnitTest: Property tests (macos-latest, Go 1.26.11) | 44 | 59 |
| MultiPlatformUnitTest: Property tests (macos-latest, Go stable) | 82 | 115 |
| MultiPlatformUnitTest: Property tests (ubuntu-latest, Go 1.26.11) | 18 | 21 |
| MultiPlatformUnitTest: Property tests (ubuntu-latest, Go stable) | 87 | 73 |
| MultiPlatformUnitTest: Property tests (windows-latest, Go 1.26.11) | 72 | 69 |
| MultiPlatformUnitTest: Property tests (windows-latest, Go stable) | 143 | 141 |
| MultiPlatformUnitTest: README and runnable Examples | 20 | 27 |
| MultiPlatformUnitTest: Unit test (macos-latest, 1.26.11) | 63 | 68 |
| MultiPlatformUnitTest: Unit test (macos-latest, stable) | 119 | 120 |
| MultiPlatformUnitTest: Unit test (ubuntu-latest, 1.26.11) | 32 | 24 |
| MultiPlatformUnitTest: Unit test (ubuntu-latest, stable) | 87 | 79 |
| MultiPlatformUnitTest: Unit test (windows-latest, 1.26.11) | 64 | 72 |
| MultiPlatformUnitTest: Unit test (windows-latest, stable) | 140 | 145 |
| MultiPlatformUnitTest: changes / changes | 5 | 10 |
| Scorecard: Scorecard analysis | 29 | n/a |
| Trivy: scan | 21 | 32 |
| Verification: benchmark | n/a | 38 |
| Verification: changes / changes | 5 | 6 |
| Verification: formal | 68 | 69 |
| Verification: policies | 20 | 25 |
| golangci-lint: changes / changes | 5 | 11 |
| golangci-lint: golangci-lint | 72 | 56 |
| golangci-lint: golangci-lint (adapters) | 39 | 44 |
| golangci-lint: golangci-lint (tests module) | 25 | 26 |
| govulncheck: changes / changes | 4 | 4 |
| govulncheck: govulncheck (., Go 1.26.11) | 34 | 33 |
| govulncheck: govulncheck (., Go stable) | 33 | 42 |
| govulncheck: govulncheck (adapters/grpc, Go 1.26.11) | n/a | 35 |
| govulncheck: govulncheck (adapters/grpc, Go stable) | n/a | 31 |
| govulncheck: govulncheck (adapters/logrus, Go 1.26.11) | 40 | 37 |
| govulncheck: govulncheck (adapters/logrus, Go stable) | 31 | 36 |
| govulncheck: govulncheck (adapters/otel, Go 1.26.11) | n/a | 44 |
| govulncheck: govulncheck (adapters/otel, Go stable) | n/a | 40 |
| govulncheck: govulncheck (adapters/sentry, Go 1.26.11) | n/a | 43 |
| govulncheck: govulncheck (adapters/sentry, Go stable) | n/a | 36 |
| govulncheck: govulncheck (adapters/zap, Go 1.26.11) | 41 | 40 |
| govulncheck: govulncheck (adapters/zap, Go stable) | 40 | 33 |
| govulncheck: govulncheck (adapters/zerolog, Go 1.26.11) | 35 | 42 |
| govulncheck: govulncheck (adapters/zerolog, Go stable) | 30 | 31 |
| govulncheck: govulncheck (tests, Go 1.26) | 47 | 33 |
| govulncheck: govulncheck (tests, Go stable) | 32 | 37 |
| reviewdog: actionlint | n/a | 9 |
| reviewdog: changes / changes | n/a | 6 |
| reviewdog: golangci-lint | n/a | 19 |
| reviewdog: misspell | n/a | 11 |

The unit workflow changed from 194 to 179 seconds while adding the three SDK modules to the existing OS and Go-version matrix. Windows stable unit time was 140 versus 145 seconds; Linux pinned unit time was 32 versus 24 seconds. These single shared-runner observations do not isolate a performance effect. The preceding head took 228 seconds, illustrating the scheduling and cache variation. reviewdog took 31 seconds, with 19 seconds in its lint job; the round-14 observation was 51 seconds. The baseline is a main push and therefore has no reviewdog run. All existing checks remain, and the new SDK modules also reach lint, gosec, govulncheck and declared-root verification.

[Support maintenance](https://github.com/sponsors/nao1215).
