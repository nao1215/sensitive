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

Mutation testing changes an expression and checks whether assertions reject the change. Surviving mutations can indicate an assertion gap, equivalent behavior or an unexecuted path; inspect each outcome before attributing a score change to stronger tests.

The testing summary is a dated measurement. After completing `make mutation > mutation.log 2>&1` and `make fuzz > fuzz.log 2>&1`, combine the root and tests-module profiles with `python3 scripts/merge_coverage.py --root-module root.cover properties.cover > coverage.out` as CI does, then run:

```sh
make testing-doc DOC_COVERAGE=coverage.out DOC_MUTATION=mutation.log DOC_FUZZ=fuzz.log
```

The timeout coefficient defaults to 10; set DOC_MUTATION_TIMEOUT to the actual value if you used a different gremlins timeout. This value and the two-worker count are recorded alongside the result.

The generator rejects incomplete mutation/fuzz runs and records source-log hashes. Commit the generated JSON, detail pages, figures and README together. Run the benchmark publication separately, after other intentional CPU workloads have finished.

## Technique inventory

<!-- techniques:start -->
<a id="examples-and-unit-tests"></a>

### Examples and unit tests

Incorrect fixed outputs and public usage contracts. Tests: [example_test](../example_test.go), [doc_test](../doc_test.go). CI: `unit_test:unit_test`.

<a id="generated-properties"></a>

### Generated properties

Combinations absent from handwritten checksum fixtures. Tests: [properties_test](../tests/properties_test.go), [properties_test](../tests/properties_test.go), [mask_test](../mask_test.go). CI: `unit_test:property_tests`.

<a id="metamorphic-relations"></a>

### Metamorphic relations

Context, kind selection, encoding or formatting changes findings. Tests: [properties_test](../tests/properties_test.go). CI: `unit_test:property_tests`.

<a id="quint-and-model-replay"></a>

### Quint and model replay

Invalid operation sequences, sticky failures and unsafe replay. Tests: [guard](../tests/models/guard.qnt), [guard_test](../embargotest/guard_test.go), [properties_test](../tests/properties_test.go). CI: `verification:formal`.

<a id="lean-reference-proofs"></a>

### Lean reference proofs

Arithmetic and interval errors beyond a finite random sample. Tests: [Reference](../tests/lean/Reference.lean), [oracles_test](../tests/oracles_test.go). CI: `verification:formal`.

<a id="intentional-snapshots"></a>

### Intentional snapshots

Unreviewed output shape changes despite correct redaction. Tests: [secret_test](../secret_test.go), [adapter_test](../adapters/zap/adapter_test.go), [guard_test](../embargotest/guard_test.go). CI: `unit_test:unit_test`.

<a id="independent-differential-oracles"></a>

### Independent differential oracles

A shared implementation mistake in locally written expected values. Tests: [oracles_test](../tests/oracles_test.go), [scanner_dispatch_test](../scanner_dispatch_test.go). CI: `verification:policies`.

<a id="structure-aware-fuzzing"></a>

### Structure-aware fuzzing

Malformed nested paths, quoted credentials and split stream frames. Tests: [fuzz_test](../fuzz_test.go), [fuzz_test](../embargotest/fuzz_test.go). CI: `fuzz:fuzz`.

<a id="mutation-testing"></a>

### Mutation testing

Assertions that execute changed logic without detecting it. Tests: [mutation_attribution](../scripts/mutation_attribution.py). CI: `heavy:mutation`.

<a id="real-logger-and-sdk-output"></a>

### Real logger and SDK output

Serializer or adapter behavior outside the scanner model. Tests: [integrations_test](../tests/integrations_test.go), [integrations_test](../tests/integrations_test.go). CI: `unit_test:property_tests`.

<a id="race-and-lifecycle-tests"></a>

### Race and lifecycle tests

Shared-state races, pipe hangs and detached goroutines. Tests: [lifecycle_test](../tests/lifecycle_test.go), [lifecycle_test](../tests/guardlifecycle/lifecycle_test.go). CI: `unit_test:property_tests`.

<a id="paired-ci-benchmarks"></a>

### Paired CI benchmarks

Speed regressions hidden by noise between runners. Tests: [ci_benchmark](../scripts/ci_benchmark.py). CI: `verification:benchmark`.

<a id="prose-and-policy-checks"></a>

### Prose and policy checks

Stale documentation and unimplemented repository rules. Tests: [check_prose](../scripts/check_prose.py), [check_policies](../scripts/check_policies.py). CI: `verification:policies`.

<a id="adversarial-budgets"></a>

### Adversarial budgets

Resource amplification, framing spoofing and ambiguous encodings. Tests: [json_test](../json_test.go), [guard_test](../embargotest/guard_test.go). CI: `heavy:scaling`.

<!-- techniques:end -->

## Measured results

<!-- testing-metrics:start -->
Measured 2026-11-15; retained snapshot with source-log hashes.

| Measurement | Result | Conditions |
|---|---|---|
| Statement coverage | 97.1% (3026/3115) | Root and integration suites combined |
| Mutation score | 88.37% | gremlins v0.6.0, root tests, 2 workers, 10x timeout |
| Mutations | 1869 killed, 246 lived, 243 uncovered, 38 timed out | Timeouts do not count as killed |
| Mutation coverage | 89.69% | Mutated statements exercised by root tests |
| Fuzzing | 13 targets, 3354049 executions | 10 seconds per target |
<!-- testing-metrics:end -->

## Measurement scope and limits

The [mutation log](performance/mutation.txt), [fuzz log](performance/fuzz.txt) and [combined coverage profile](performance/coverage.txt) support the dated summary above. Their content hashes are recorded in testing-metrics.json. This snapshot is retained evidence, not a measurement of every subsequent edit. Gremlins used two workers and GOMAXPROCS=4. Timeouts do not count as kills; root-test instrumentation does not cover every nested-module and child-process path. Mutation coverage is narrower than combined statement coverage.

The coverage gate measures root-module packages from `go list ./...`, including internal detectors and embargotest. Integration tests contribute coverage for those packages; nested test-tool and adapter modules do not enter the denominator. `scripts/merge_coverage.py --root-module root.cover properties.cover` enforces that scope, and CI requires at least 97%. Neither a coverage percentage nor a mutation score proves that arbitrary secrets cannot leak.

Use `scripts/mutation_attribution.py --output /tmp/mutation-attribution.json` to replay selected expression changes separately against bitmap, adversarial, snapshot, fuzz seed, model, metamorphic and oracle assertions. The tool first requires every unmodified test group to pass and restores each mutation before the next probe. Equality-boundary changes that cannot alter the externally observable result remain equivalent survivors; focused probes are not a substitute for the scheduled full mutation run.

## Technique scope

Metamorphic relations compare a line with independent clean lines around it, line permutations, separate and combined kind selections, percent-encoded email spans, repeated masking, compact and pretty JSON, and real slog output. These catch transformations that break consistency even when each individual output looks plausible. The generated independent lines avoid cross-record context: raw Scan uses bounded context windows that may cross a newline, so a keyword in one line and an ambiguous candidate in another are not independent. Inserting a business label inside a line can intentionally change confidence; ScanLines provides explicit record isolation. Percent decoding is one layer; credential grammar still depends on original delimiters. The optional real-log replay uses the checksum-pinned cache and never commits raw log lines. Every line checks padding, idempotence, the union of two disjoint kind sets, and JSON/slog agreement. Email encoding excludes already-percent-escaped lines because the decoder has one layer. The first 64 adjacent pairs per dataset also check permutation with long clean separators that isolate context windows. The held split has been seen and is now regression data, not an independent estimate for new policy decisions.

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

My Number cannot reject every single-digit change: its definition maps two residues to check digit zero. The Lean counterexample changes the first body digit of 000000000000 to two while retaining check digit zero. The vectors retain that counterexample; inventing a stronger rejection rule would disagree with the specified algorithm. Verhoeff is not added because Aadhaar is not a detector in the supported detector set. Proofs of arbitrary parser code, whole-program concurrency and custom formatter termination cost more than their present benefit; generated properties, race tests and process timeouts cover their bounded observable contracts.

The offline external oracle is python-stdnum 2.2, distributed as its unmodified wheel with its bundled license and verified SHA256. It supplies independent Luhn, IBAN and BIC implementations. Generated ASCII email syntax is compared with net/mail over the shared subset; IP syntax uses net/netip with embargo's explicit local-address exclusions. Display names, comments, quoted email local parts and registered-bank existence are outside that intersection. Python accepts some MOD 97-valid IBANs with reserved check digits 00, 01 or 99; embargo rejects those by policy. This is a documented difference, not a new accuracy claim. BIC country membership is checked, not bank ownership. A mismatch outside those explicit differences fails the suite.

The existing nightly GitHub-hosted Go fuzz workflow now discovers the full target inventory through one script used by Make and CI. New grammars keep JSON paths, credential quoting and Guard write boundaries structurally meaningful; an additional bounded-input target checks processing cost, allocated bytes and valid single-record log framing. Seeds include synthetic reproductions of real-log false-positive shapes. ClusterFuzzLite would add a second fuzz engine and build interface without a new tested property here; native Go fuzzing remains the continuous engine. Scorecard recognizes native Go Fuzz functions; full SHA action pins remain independent of that signal. Crashing inputs are uploaded for review and regression retention.

Same-runner benchmarks build base and head once and alternate ten measurements in both orders. Benchstat output and raw samples appear in the job summary and artifact. The clean and dirty default-scanner medians each fail above +20% versus base; existing zero-allocation tests and bounded allocation amplification tests remain gates. Accuracy and real-log FP/GB budgets run in separate detector-change jobs; see the [frozen thresholds](ci.md#detector-quality-gates). The scheduled heavy matrix adds large adversarial inputs without charging every push for 16 MB cases or full mutation runs.

## Snapshot and generated-document review

| Artifact | Content property before equality | Check |
|---|---|---|
| Public API goldens | Constants are included; promoted members are rejected | contracts/api_test.go |
| Logger event snapshots | Valid JSON, no canary/email, retained nested object and array fields | Each adapter secret_test.go |
| Guard failure message | Active test names survive validation; canaries and rejected names do not | embargotest/guard_test.go and guard_test.go |
| Large MaskJSON snapshot | Every sensitive field removed; exact integer and public fields retained | secret_test.go |
| Accuracy tables and figures | Unique exact-span matching, valid counters and measured-data rendering | accuracy_test.go and test_accuracy_figures.py |
| Benchmark tables and figures | Parsed samples, confidence intervals and masking correctness | tests/docs_test.go and tests/benchmark_test.go |
| Compatibility and leak tables | Real serializer/SDK/HTTP outputs satisfy masking assertions | tests/integrations_test.go and tests/comparison_test.go |
| Comparison and real-log documents | Measured samples, pinned inputs and explicit classification totals | test_comparison_docs.py and test_real_logs.py |
| Testing metrics | Completed logs, denominator scope and full fuzz inventory | tests/docs_test.go and testing_docs.py |
| Policy and technique tables | Every row names a real check and CI entry | check_policies.py and testing_techniques.py |

A golden diff is reviewed as an output contract change. Updating a golden cannot suppress its semantic assertions. Generated tables remain dated measurements; equality checks prevent accidental drift and property checks validate the measurement pipeline, not the truth of an unreviewed label.

README-linked example files are parsed on their own and compiled in temporary consumer modules, with only public module imports and local replacements to the tested checkout. The check retains every example body and Output assertion, renames API-specific example names only for file-only vet, and serializes child Go commands. Missing private helpers or repository fixtures fail the check. Default-policy checks also reject stale all-detector and entropy claims.

[Support maintenance](https://github.com/sponsors/nao1215).
