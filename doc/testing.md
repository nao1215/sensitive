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

The testing summary is a dated measurement. After completing `make mutation > mutation.log 2>&1` and `make fuzz > fuzz.log 2>&1`, combine the root and tests-module profiles with `python3 scripts/merge_coverage.py root.cover properties.cover > coverage.out` as CI does, then run:

```sh
make testing-doc DOC_COVERAGE=coverage.out DOC_MUTATION=mutation.log DOC_FUZZ=fuzz.log DOC_COMMIT="$(git rev-parse HEAD)"
```

The timeout coefficient defaults to 100; set DOC_MUTATION_TIMEOUT to the actual value if you used a different gremlins timeout. This value and the four-worker count are recorded alongside the result.

The generator rejects incomplete mutation/fuzz runs and records source-log hashes. Commit the generated JSON, detail pages, figures and README together. Run the benchmark publication separately, after other intentional CPU workloads have finished.

## Measured results

<!-- testing-metrics:start -->
Measured 2026-11-15 at [7d54404](https://github.com/nao1215/embargo/commit/7d54404faaecbc271d95f8ad6751fc063e64b65a).

| Measurement | Result | Conditions |
|---|---|---|
| Statement coverage | 96.8% (2453/2533) | Root and integration suites combined |
| Mutation score | 90.68% | gremlins v0.6.0, root tests, 4 workers, 10x timeout |
| Mutations | 1517 killed, 156 lived, 124 uncovered, 37 timed out | Timeouts do not count as killed |
| Mutation coverage | 93.10% | Mutated statements exercised by root tests |
| Fuzzing | 7 targets, 2949231 executions | 10 seconds per target |
<!-- testing-metrics:end -->
