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

The timeout coefficient defaults to 10; set DOC_MUTATION_TIMEOUT to the actual value if you used a different gremlins timeout. This value and the two-worker count are recorded alongside the result.

The generator rejects incomplete mutation/fuzz runs and records source-log hashes. Commit the generated JSON, detail pages, figures and README together. Run the benchmark publication separately, after other intentional CPU workloads have finished.

## Technique inventory

<!-- techniques:start -->
<a id="examples-and-unit-tests"></a>

### Examples and unit tests

Incorrect fixed outputs and public usage contracts. Tests: [example_test](../example_test.go), [doc_sync_test](../doc_sync_test.go). CI: `unit_test:unit_test`.

<a id="generated-properties"></a>

### Generated properties

Combinations absent from handwritten checksum fixtures. Tests: [properties_test](../tests/properties_test.go), [mask_test](../tests/mask_test.go), [mask_oracle_test](../mask_oracle_test.go). CI: `unit_test:property_tests`.

<a id="metamorphic-relations"></a>

### Metamorphic relations

Context, kind selection, encoding or formatting changes findings. Tests: [metamorphic_test](../tests/metamorphic_test.go). CI: `unit_test:property_tests`.

<a id="quint-and-model-replay"></a>

### Quint and model replay

Invalid operation sequences, sticky failures and unsafe replay. Tests: [guard](../tests/models/guard.qnt), [model_replay_test](../embargotest/model_replay_test.go), [model_input_test](../tests/model_input_test.go). CI: `verification:formal`.

<a id="lean-reference-proofs"></a>

### Lean reference proofs

Arithmetic and interval errors beyond a finite random sample. Tests: [Reference](../tests/lean/Reference.lean), [lean_vectors_test](../tests/lean_vectors_test.go). CI: `verification:formal`.

<a id="intentional-snapshots"></a>

### Intentional snapshots

Unreviewed output shape changes despite correct redaction. Tests: [snapshot_test](../snapshot_test.go), [snapshot_test](../adapters/zap/snapshot_test.go), [guard_test](../embargotest/guard_test.go). CI: `unit_test:unit_test`.

<a id="independent-differential-oracles"></a>

### Independent differential oracles

A shared implementation mistake in locally written expected values. Tests: [external_oracles_test](../tests/external_oracles_test.go), [scanner_dispatch_test](../scanner_dispatch_test.go). CI: `verification:policies`.

<a id="structure-aware-fuzzing"></a>

### Structure-aware fuzzing

Malformed nested paths, quoted credentials and split stream frames. Tests: [structure_fuzz_test](../structure_fuzz_test.go), [guard_fuzz_test](../embargotest/guard_fuzz_test.go). CI: `fuzz:fuzz`.

<a id="mutation-testing"></a>

### Mutation testing

Assertions that execute changed logic without detecting it. Tests: [mutation_attribution](../scripts/mutation_attribution.py). CI: `heavy:mutation`.

<a id="real-logger-and-sdk-output"></a>

### Real logger and SDK output

Serializer or adapter behavior outside the scanner model. Tests: [compatibility_integration_test](../tests/compatibility_integration_test.go), [telemetry_logs_test](../tests/telemetry_logs_test.go). CI: `unit_test:property_tests`.

<a id="race-and-lifecycle-tests"></a>

### Race and lifecycle tests

Shared-state races, pipe hangs and detached goroutines. Tests: [lifecycle_test](../tests/lifecycle_test.go), [main_test](../tests/guardlifecycle/main_test.go). CI: `unit_test:property_tests`.

<a id="paired-ci-benchmarks"></a>

### Paired CI benchmarks

Speed regressions hidden by noise between runners. Tests: [ci_benchmark](../scripts/ci_benchmark.py). CI: `verification:benchmark`.

<a id="prose-and-policy-checks"></a>

### Prose and policy checks

Stale documentation and unimplemented repository rules. Tests: [check_prose](../scripts/check_prose.py), [check_policies](../scripts/check_policies.py). CI: `verification:policies`.

<a id="adversarial-budgets"></a>

### Adversarial budgets

Resource amplification, framing spoofing and ambiguous encodings. Tests: [adversarial_test](../adversarial_test.go), [guard_adversarial_test](../embargotest/guard_adversarial_test.go). CI: `heavy:scaling`.

<!-- techniques:end -->

## Measured results

<!-- testing-metrics:start -->
Measured 2026-11-15 at [c7685ad](https://github.com/nao1215/embargo/commit/c7685adc40edbbad3ef87f28b813f68023db9fa8).

| Measurement | Result | Conditions |
|---|---|---|
| Statement coverage | 97.1% (3026/3115) | Root and integration suites combined |
| Mutation score | 88.37% | gremlins v0.6.0, root tests, 2 workers, 10x timeout |
| Mutations | 1869 killed, 246 lived, 243 uncovered, 38 timed out | Timeouts do not count as killed |
| Mutation coverage | 89.69% | Mutated statements exercised by root tests |
| Fuzzing | 13 targets, 3354049 executions | 10 seconds per target |
<!-- testing-metrics:end -->

## Round 13 measurement boundary

The [mutation log](performance/round13-mutation.txt), [fuzz log](performance/round13-fuzz.txt) and [combined root coverage profile](performance/round13-coverage.txt) retain the completed evidence for a7dd142. The later trailing-context SWIFT assertion is measured separately in the focused follow-up. The root and integration profiles instrument dependencies for statement coverage; adapter and tests-module source blocks are excluded from that root total. Gremlins uses its default per-package root-test mode and walks nested source directories, so its uncovered count also includes uninstrumented child-process paths, parser paths exercised from another package, and nested-module source. Mutation coverage is therefore narrower than combined statement coverage; neither percentage proves that arbitrary secrets cannot leak.

The full-run efficacy changed from 90.06% in round 12 to 88.26%; exercised mutations changed from 85.48% to 90.57%. More covered mutations also exposed more missing assertions. The [round 13 survivor review](mutation-review.md#round-13-log-context-boundaries) records a separate changed-lines run with all root tests and the boundary tests added afterward. Its focused score does not replace the full-run score above.

The round-13 root mutation command used four workers and timeout coefficient 10; round 14 caps workers at two. Timeouts remain a separate category. The nine ten-second fuzz runs completed under GOMAXPROCS=4; their execution counts are observations, not a stable throughput benchmark. The Guard fixture separately exercises real process output, timeout/overflow, parallel tests and inherited child descriptors, and the CI matrix runs its goleak lifecycle on Linux, Windows and macOS.

The coverage gate measures root-module packages from `go list ./...`, including internal detectors and embargotest. Integration tests contribute coverage for those packages; nested test-tool and adapter modules do not enter the denominator. `scripts/merge_coverage.py --root-module root.cover properties.cover` enforces that scope, and CI requires at least 97%. The cached-log command is exercised by the real-log measurement, separately from this library statement metric.
## Round 14 measurement boundary

The [full mutation log](performance/round14-mutation.txt), [fuzz log](performance/round14-fuzz.txt) and [combined coverage profile](performance/round14-coverage.txt) retain the c7685ad measurement. Gremlins ran alone with two workers and GOMAXPROCS=4. The [matched survivor review](mutation-review.md#round-14-technique-attribution) separates source changes, newly covered equivalent tie comparisons, nested-tool coverage gaps and timeout transitions. A later zero-width Mask boundary assertion is measured through focused attribution; it is not folded into the published full-run score. Real-log metamorphic checks and snapshot shape assertions were also strengthened afterward without changing runtime code.

## Round 14 technique decisions

Metamorphic relations compare a line with independent clean lines around it, line permutations, separate and combined kind selections, percent-encoded email spans, repeated masking, compact and pretty JSON, and real slog output. These catch transformations that break consistency even when each individual output looks plausible. The generated independent lines avoid cross-record context: raw Scan uses bounded context windows that may cross a newline, so a keyword in one line and an ambiguous candidate in another are not independent. Inserting a business label inside a line can intentionally change confidence; ScanLines provides explicit record isolation. Percent decoding is one layer; credential grammar still depends on original delimiters. The optional real-log replay uses the checksum-pinned round-13 cache and never commits raw log lines. Every line checks padding, idempotence, the union of two disjoint kind sets, and JSON/slog agreement. Email encoding excludes already-percent-escaped lines because the decoder has one layer. The first 64 adjacent pairs per dataset also check permutation with long clean separators that isolate context windows. The round-13 held split has been seen and is now regression data, not an independent estimate for new policy decisions.

Quint 0.33.1 models Input initialization/failure/snapshots, Recorder writer/expectation/check/cleanup sequences, and Guard parent/child stream limits, exit failures, timeouts, scanner failures and replay. Each model runs 64 simulator traces of 12 transitions and Apalache 0.62.4 checks the invariant to depth eight. Committed deterministic traces are replayed against the Go objects; Guard also drives real child processes and pipes. This reaches combinations that isolated lifecycle examples do not enumerate. The bounds are explicit, and the sequential model does not prove concurrent scheduling or arbitrary custom-detector termination.

```sh
npm ci --prefix tests/models --ignore-scripts
python3 scripts/quint_models.py --check
go test ./embargotest -run '^TestQuint' -count=1
go -C tests test . -run '^TestQuint' -count=1
```

Quint's model checker requires Java 21. The simulator uses one worker so fixed-seed traces remain reproducible without allocating a host-sized worker pool. Guard sampling favors writes and rejects a trace set missing overflow, timeout, scanner failure, child failure or safe replay. The 64 traces contain 47 unique sequences; ten reach overflow, including combinations with child exit, timeout and scanner failure. Model checking still explores the same transition relation. The script verifies model-source hashes, regenerates the fixed-seed traces and rejects drift. CI replays 64 traces per model; the simulator and model checker run in their own job. The original scanner-failure model allowed failure on an empty stream; replay exposed that invalid abstraction because Scan(empty) does not invoke a custom detector. The model now requires bytes before that transition.

Lean 4.35.0 checks reference arithmetic and range semantics without external theorem packages. The proofs cover Luhn's doubled-digit textbook identity and single-digit residue separation, streaming MOD 97 versus whole-number division, nonzero decimal-place residues, My Number's position weights, monotone bounded percent-position maps, and exact interval-union replacement for valid ranges. Invalid Go finding ranges instead use the separately tested fail-closed policy. The compiled reference produces 12,574 vectors consumed by the Go tests, including exact encoded spans and overlapping mask ranges. These prove reference properties and test correspondence with Go; they do not constitute a proof of the Go parser or runtime.

```sh
python3 scripts/install_verification.py /tmp/embargo-formal
export PATH=/tmp/embargo-formal/lean-4.35.0-linux/bin:$PATH
python3 scripts/check_lean.py
```

My Number cannot reject every single-digit change: its definition maps two residues to check digit zero. The Lean counterexample changes the first body digit of 000000000000 to two while retaining check digit zero. The vectors retain that counterexample; inventing a stronger rejection rule would disagree with the specified algorithm. Verhoeff is not added because Aadhaar is not a detector in this round. Proofs of arbitrary parser code, whole-program concurrency and custom formatter termination cost more than their present benefit; generated properties, race tests and process timeouts cover their bounded observable contracts.

The offline external oracle is python-stdnum 2.2, distributed as its unmodified wheel with its bundled license and verified SHA256. It supplies independent Luhn, IBAN and BIC implementations. Generated ASCII email syntax is compared with net/mail over the shared subset; IP syntax uses net/netip with embargo's explicit local-address exclusions. Display names, comments, quoted email local parts and registered-bank existence are outside that intersection. Python accepts some MOD 97-valid IBANs with reserved check digits 00, 01 or 99; embargo rejects those by policy. This is a documented difference, not a new accuracy claim. BIC country membership is checked, not bank ownership. A mismatch outside those explicit differences fails the suite.

The existing nightly GitHub-hosted Go fuzz workflow now discovers the full target inventory through one script used by Make and CI. New grammars keep JSON paths, credential quoting and Guard write boundaries structurally meaningful; an additional bounded-input target checks processing cost, allocated bytes and valid single-record log framing. Seeds include synthetic reproductions of real-log false-positive shapes. ClusterFuzzLite would add a second fuzz engine and build interface without a new tested property here; native Go fuzzing remains the continuous engine. Scorecard recognizes native Go Fuzz functions; full SHA action pins remain independent of that signal. Crashing inputs are uploaded for review and regression retention.

Same-runner benchmarks build base and head once and alternate ten measurements in both orders. Benchstat output and raw samples appear in the job summary and artifact. Wall time is not a merge gate; existing zero-allocation tests and bounded allocation amplification tests are. The scheduled heavy matrix adds large adversarial inputs without charging every push for 16 MB cases or full mutation runs.

## Snapshot and generated-document review

| Artifact | Content property before equality | Check |
|---|---|---|
| Public API goldens | Constants are included; promoted members are rejected | contracts/api_test.go |
| Logger event snapshots | Valid JSON, no canary/email, retained nested object and array fields | Each adapter snapshot_test.go |
| Guard failure message | Active test names survive validation; canaries and rejected names do not | guard_adversarial_test.go and guard_test.go |
| Large MaskJSON snapshot | Every sensitive field removed; exact integer and public fields retained | snapshot_test.go |
| Accuracy tables and figures | Unique exact-span matching, valid counters and measured-data rendering | accuracy_test.go and test_accuracy_figures.py |
| Benchmark tables and figures | Parsed samples, confidence intervals and masking correctness | benchmark_docs_test.go and log_benchmark_contract_test.go |
| Compatibility and leak tables | Real serializer/SDK/HTTP outputs satisfy masking assertions | compatibility_integration_test.go and leak_scenarios_test.go |
| Comparison and real-log documents | Measured samples, pinned inputs and explicit classification totals | test_comparison_docs.py and test_real_logs.py |
| Testing metrics | Completed logs, denominator scope and full fuzz inventory | testing_docs_test.go and testing_docs.py |
| Policy and technique tables | Every row names a real check and CI entry | check_policies.py and testing_techniques.py |

A golden diff is reviewed as an output contract change. Updating a golden cannot suppress its semantic assertions. Generated tables remain dated measurements; equality checks prevent accidental drift and property checks validate the measurement pipeline, not the truth of an unreviewed label.

[Support maintenance](https://github.com/sponsors/nao1215).
