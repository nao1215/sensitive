# Testing

The root suite checks formats, checksums, masking and output lifecycle rules. Generated cases exercise boundaries and transformations; fuzzing searches for panics and broken invariants. The [test-only module](../tests/README.md) documents rapid generators, automatic shrinking, the independent checksum oracles, and periodic gremlins mutation measurements.

Run from the repository root:

```sh
go test ./...
go vet ./...
golangci-lint run
(cd tests && go test ./... && go vet ./... && golangci-lint run --config ../.golangci.yml)
```

Explore new inputs with `go test . -fuzz=FuzzScanner -fuzztime=2m` and measure performance with `make benchmark`. Review API changes before accepting `UPDATE_API=1 go -C tests test ./contracts`. `make test` generates coverage reports and `make lint` runs the root linter.

README examples carry an `example: file:function` marker; test snippets use `test: file:function`. `TestReadmeExamples` compares each block to its runnable example, including expected output; update both together. `TestExamplesAppearInGodoc` checks that Go's documentation parser requires a recognized nonempty Output for every exported runtime identifier, including constants and interface methods.

`make accuracy-doc` regenerates exact-span precision and recall from the labeled fixtures. `make compatibility-doc` regenerates the tested-output table by executing the real integrations. `make benchmark-doc` runs the published benchmark matrix and records its raw samples and environment. Ordinary Go tests reject stale snapshots and text. Python tests compare generated SVG bytes with the same measured data.

The [detector and scanner mutation review](mutation-review.md) compares the baseline and revised suite, lists surviving mutants and separates equivalence arguments from unresolved assertions.

The testing summary is a dated measurement. After completing `make mutation > mutation.log 2>&1` and `make fuzz > fuzz.log 2>&1`, combine the root and tests-module profiles with `python3 scripts/merge_coverage.py --root-module root.cover properties.cover > coverage.out` as CI does, then run:

```sh
make testing-doc DOC_COVERAGE=coverage.out DOC_MUTATION=mutation.log DOC_FUZZ=fuzz.log DOC_COMMIT="$(git rev-parse HEAD)"
```

The timeout coefficient defaults to 100; set DOC_MUTATION_TIMEOUT to the actual value if you used a different gremlins timeout. This value and the four-worker count are recorded alongside the result.

The generator rejects incomplete mutation/fuzz runs and records source-log hashes. Commit the generated JSON, detail pages, figures and README together. Run the benchmark publication separately, after other intentional CPU workloads have finished.

## Measured results

<!-- testing-metrics:start -->
Measured 2026-11-15 at [a7dd142](https://github.com/nao1215/embargo/commit/a7dd142532cdcddf8237ba0d099827d27154bf6e).

| Measurement | Result | Conditions |
|---|---|---|
| Statement coverage | 97.1% (3032/3123) | Root and integration suites combined |
| Mutation score | 88.26% | gremlins v0.6.0, root tests, 4 workers, 10x timeout |
| Mutations | 1864 killed, 248 lived, 220 uncovered, 39 timed out | Timeouts do not count as killed |
| Mutation coverage | 90.57% | Mutated statements exercised by root tests |
| Fuzzing | 9 targets, 2388415 executions | 10 seconds per target |
<!-- testing-metrics:end -->

## Round 13 measurement boundary

The [mutation log](performance/round13-mutation.txt), [fuzz log](performance/round13-fuzz.txt) and [combined root coverage profile](performance/round13-coverage.txt) retain the completed evidence for a7dd142. The later trailing-context SWIFT assertion is measured separately in the focused follow-up. The root and integration profiles instrument dependencies for statement coverage; adapter and tests-module source blocks are excluded from that root total. Gremlins uses its default per-package root-test mode and walks nested source directories, so its uncovered count also includes uninstrumented child-process paths, parser paths exercised from another package, and nested-module source. Mutation coverage is therefore narrower than combined statement coverage; neither percentage proves that arbitrary secrets cannot leak.

The full-run efficacy changed from 90.06% in round 12 to 88.26%; exercised mutations changed from 85.48% to 90.57%. More covered mutations also exposed more missing assertions. The [round 13 survivor review](mutation-review.md#round-13-log-context-boundaries) records a separate changed-lines run with all root tests and the boundary tests added afterward. Its focused score does not replace the full-run score above.

The existing root mutation command uses four workers. This run explicitly used timeout coefficient 10. Timeouts remain a separate category. The nine ten-second fuzz runs completed under GOMAXPROCS=4; their execution counts are observations, not a stable throughput benchmark. The Guard fixture separately exercises real process output, timeout/overflow, parallel tests and inherited child descriptors, and the CI matrix runs its goleak lifecycle on Linux, Windows and macOS.

The coverage gate measures root-module packages from `go list ./...`, including internal detectors and embargotest. Integration tests contribute coverage for those packages; nested test-tool and adapter modules do not enter the denominator. `scripts/merge_coverage.py --root-module root.cover properties.cover` enforces that scope, and CI requires at least 97%. The cached-log command is exercised by the real-log measurement, separately from this library statement metric.
