# CI timing and execution policy

Round 14 compares PR #81 head `5ae14696d60444869b7020aa62814bbcb63fb15a` with this PR. Workflow time is creation to the final job completion, including queue and dependencies; job time is started_at to completed_at. Raw GitHub timestamps are collected with gh run list and the Actions jobs API. Head values are pending until the PR runs; no local duration is substituted for GitHub time.

| Workflow | Base seconds | Head seconds |
|---|---:|---:|
| Coverage | 84.0 | Pending |
| golangci-lint | 128.0 | Pending |
| MultiPlatformUnitTest | 134.0 | Pending |
| reviewdog | 27.0 | Pending |
| govulncheck | 50.0 | Pending |
| Trivy | 25.0 | Pending |
| Gosec | 72.0 | Pending |
| CodeQL | 68.0 | Pending |

| Job | Base seconds | Head seconds |
|---|---:|---:|
| Coverage: changes / changes | 3 | Pending |
| Coverage: Unit test (linux) (ubuntu-latest) | 75 | Pending |
| golangci-lint: changes / changes | 5 | Pending |
| golangci-lint: golangci-lint (tests module) | 20 | Pending |
| golangci-lint: golangci-lint | 118 | Pending |
| golangci-lint: golangci-lint (adapters) | 39 | Pending |
| MultiPlatformUnitTest: README and runnable Examples | 27 | Pending |
| MultiPlatformUnitTest: changes / changes | 5 | Pending |
| MultiPlatformUnitTest: Cross build (netbsd) | 17 | Pending |
| MultiPlatformUnitTest: Property tests (macos-latest, Go stable) | 74 | Pending |
| MultiPlatformUnitTest: Property tests (macos-latest, Go 1.26.11) | 75 | Pending |
| MultiPlatformUnitTest: Property tests (windows-latest, Go 1.26.11) | 59 | Pending |
| MultiPlatformUnitTest: Cross build (freebsd) | 28 | Pending |
| MultiPlatformUnitTest: Property tests (ubuntu-latest, Go 1.26.11) | 28 | Pending |
| MultiPlatformUnitTest: Property tests (ubuntu-latest, Go stable) | 24 | Pending |
| MultiPlatformUnitTest: Cross build (openbsd) | 32 | Pending |
| MultiPlatformUnitTest: Property tests (windows-latest, Go stable) | 58 | Pending |
| MultiPlatformUnitTest: Unit test (ubuntu-latest, stable) | 54 | Pending |
| MultiPlatformUnitTest: Unit test (macos-latest, stable) | 47 | Pending |
| MultiPlatformUnitTest: Unit test (macos-latest, 1.26.11) | 104 | Pending |
| MultiPlatformUnitTest: Unit test (windows-latest, 1.26.11) | 123 | Pending |
| MultiPlatformUnitTest: Unit test (ubuntu-latest, 1.26.11) | 44 | Pending |
| MultiPlatformUnitTest: Unit test (windows-latest, stable) | 82 | Pending |
| reviewdog: changes / changes | 3 | Pending |
| reviewdog: misspell | 10 | Pending |
| reviewdog: golangci-lint | 18 | Pending |
| reviewdog: actionlint | 7 | Pending |
| govulncheck: changes / changes | 3 | Pending |
| govulncheck: govulncheck (., Go 1.26.11) | 35 | Pending |
| govulncheck: govulncheck (adapters/zerolog, Go 1.26.11) | 32 | Pending |
| govulncheck: govulncheck (., Go stable) | 35 | Pending |
| govulncheck: govulncheck (adapters/logrus, Go stable) | 32 | Pending |
| govulncheck: govulncheck (tests, Go 1.26) | 35 | Pending |
| govulncheck: govulncheck (adapters/zerolog, Go stable) | 28 | Pending |
| govulncheck: govulncheck (adapters/zap, Go stable) | 35 | Pending |
| govulncheck: govulncheck (adapters/zap, Go 1.26.11) | 40 | Pending |
| govulncheck: govulncheck (adapters/logrus, Go 1.26.11) | 40 | Pending |
| govulncheck: govulncheck (tests, Go stable) | 39 | Pending |
| Trivy: scan | 22 | Pending |
| Gosec: scan (adapters/logrus) | 27 | Pending |
| Gosec: scan (.) | 69 | Pending |
| Gosec: scan (tests) | 57 | Pending |
| Gosec: scan (adapters/zerolog) | 28 | Pending |
| Gosec: scan (adapters/zap) | 30 | Pending |
| CodeQL: Analyze (go) | 65 | Pending |

The slowest baseline jobs were the Windows minimum-Go unit leg (123 seconds), enforced root lint (118 seconds) and macOS minimum-Go unit leg (104 seconds). Root lint spent 34 seconds resolving/running architecture checks and 66 seconds in the negative-fixture step, which installed golangci-lint again after its action had already installed the same version and added it to PATH. Round 14 reuses that binary. The six unit legs previously produced unused coverage profiles; Coverage retains the instrumented root and integration runs and the 97% gate, while the OS matrix executes the tests without redundant instrumentation.

Minimum and stable Go remain on Linux, Windows and macOS. Stable legs run the race detector for the root, tests and adapter modules; minimum-Go legs retain ordinary tests. Adapter race coverage remains on all three OSes without repeating it in both toolchain legs. Documentation-only changes continue to skip code jobs while documentation and policy checks run. Formal verification and paired benchmarks use the same change classification; heavy mutation and scaling run weekly, and fuzz search runs nightly. Shared runners and cache state affect the timing table, so an observed delta is not attributed solely to one edit.

CodeRabbit reviews the Lean and Quint source, generators and replay assertions; regenerated vector and trace bulk is excluded from prose review while formal CI checks exact staleness. Intentional output snapshots remain reviewable. Verification adds bounded formal-model checks, Lean compilation, policy checks and paired benchmarks. Exact job and step durations will be recorded from the PR run. Each future round report must retain a workflow/job timing table, commit IDs, slowest-job causes and the effect of any CI edit. Do not omit a check merely to improve the table.

[Support maintenance](https://github.com/sponsors/nao1215).
