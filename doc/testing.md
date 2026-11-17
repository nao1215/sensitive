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

## Package mutation gate

`make mutation` runs [Gremlins v0.6.0](https://github.com/go-gremlins/gremlins/releases/tag/v0.6.0) through the tools module; the root module has no tool dependency. The scheduled/manual heavy workflow checks every root package and the audit command, one gremlins run per package so each timeout is ten times that package's own test time; `make mutation` uses up to four workers (two on a 4-CPU runner) with GOMAXPROCS=2 each, a 4 GiB address-space cap that turns runaway allocation into a fast out-of-memory failure, and EMBARGO_MUTATION=1 to skip the README compile check, whose examples' Output assertions still run. It rejects scores or mutation coverage below [the recorded package floors](mutation-baseline.json). gremlins times the build of each mutated package together with its tests, so a mutant compiled while other workers hold the CPU can time out without being slower. The wrapper therefore rebuilds every timed-out mutant alone, with the same operator replacement supplied through a Go build overlay, and times only its test binary against ten times the unmutated binary's run (at least 10 s). A mutant that fails is killed, one that passes lived, and one that still times out, such as a loop whose counter now moves away from its bound, stays timed out. Timeouts that persist count as un-killed executed mutants: score = killed / (killed + lived + timed out). Mutation coverage divides that executed count by executed plus uncovered mutants. The older dated summary below uses the tool's killed / (killed + lived) efficacy; it is not the new gate's denominator.

`make mutation-diff BASE=origin/main` mutates only lines changed since BASE and lists surviving, timed-out and uncovered mutants on them; it checks no floors and is meant for work in progress. Every run first verifies a known killed expression and a known surviving expression, then compares all measured expression coordinates with a fresh dry-run inventory. The wrapper clears the Go test cache after inventory collection so the campaign timeout comes from an actual test run. This prevents missing files, truncated reports or a failing test launcher from creating a passing score. v0.6.0 mispasses its own --test-cpu flag, so the wrapper sets GOMAXPROCS instead. Its nested package-main mapping is also incorrect; the audit command runs as a temporary root module with the same command source, tests and scanner snapshot. No third-party source is patched.

[Recorded expression outcomes and source fingerprints](performance/mutation-baseline.json) support the baseline; `python3 scripts/mutation_gate.py --check-evidence` rejects a mismatch between those outcomes and the package scores. Reports from future full runs are uploaded as workflow artifacts. Use `python3 scripts/mutation_gate.py --record` only after reviewing a complete run; it refuses to lower an existing floor. Surviving equivalent comparisons, capacity changes and defensive branches are retained as survivors, never relabeled as kills.

<!-- mutation-baseline:start -->
| Package | Score floor | Mutation coverage floor | Killed | Lived | Timed out | Uncovered |
|---|---:|---:|---:|---:|---:|---:|
| . | 83.33% | 99.78% | 370 | 58 | 16 | 1 |
| cmd/embargo | 96.92% | 100.00% | 63 | 1 | 1 | 0 |
| embargotest | 90.98% | 98.79% | 222 | 19 | 3 | 3 |
| internal/ascii | 100.00% | 100.00% | 58 | 0 | 0 | 0 |
| internal/detect | 87.56% | 92.35% | 1872 | 233 | 33 | 177 |
| internal/output | 82.35% | 100.00% | 56 | 10 | 2 | 0 |
| internal/saferecord | 100.00% | 100.00% | 5 | 0 | 0 | 0 |
<!-- mutation-baseline:end -->

## Coverage triage and changed statements

CI merges root and tests-module coverage and retains the 97% total floor. Every added or changed root-module statement must also be covered. `scripts/diff_coverage.py` checks the actual Go statement blocks against the pull-request diff, inventories all root packages, and rejects missing instrumentation. [Coverage exceptions](coverage-exceptions.json) name exact source ranges, their content hashes and reasons; a source edit invalidates an exception until it is reviewed again.

Boundary tests cover invalid checksum lengths and alphabets, reserved routing districts, malformed tokens, full Keccak blocks, canary encodings and fragment limits, child environment propagation, HTTP outcome flags, overlapping-kind priority, repeated terminal keywords, canceled slog enablement and cancellation between detectors. Unused exported internal detector wrappers and unreachable keyword branches have been removed. `jsonError.Error` and the Guard parent supervisor now have complete statement coverage with assertions on diagnostics, actual child streams, exit failures and withheld replay.

The remaining exceptions fall into four groups: standard-library encoding failures for strings, bytes and string-only maps; decoder states excluded by prior validation; process entry points and unavailable executable paths tested through child processes whose counters are not merged; and adjacent cancellation checks or private slog kinds that cannot be targeted deterministically through supported APIs. Guard still exercises its actual TestMain path in compiled fixtures; its supervisor is measured in-process. These exceptions permit coverage accounting only and never bypass masking, accuracy, scaling or output-schema assertions.

| Remaining function | Missing path and disposition |
|---|---|
| cmd/embargo.main; embargotest.Guard | Child fixtures assert entry points; run, exitCode and guardParent are measured in-process. |
| embargotest.Run; embargotest.Guard | os.Executable failure is not portable to induce in an already running Go test binary. |
| embargotest.guardMessage | Replacing process-wide stderr disturbs other tests; replay and child diagnostics are asserted. |
| embargotest.representations; embargotest.recordHeaders; maskHTTPHeaders; appendString; sanitizeBytes | encoding/json cannot fail for the concrete string, byte slice and string-only map types passed here. |
| embargotest.jsonValue; stringValue | Decoder invariants or prior whole-document validation exclude these malformed states. |
| sanitizeAttr | Adjacent cancellation races and private slog kinds cannot be selected through supported APIs. |

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
Measured 2026-11-17; retained snapshot with source-log hashes.

| Measurement | Result | Conditions |
|---|---|---|
| Statement coverage | 99.4% (4809/4837) | Root and integration suites combined |
| Mutation score | 89.18% | gremlins v0.6.0, root tests, 2 workers, 10x timeout |
| Mutations | 2646 killed, 321 lived, 181 uncovered, 55 timed out | Timeouts do not count as killed |
| Mutation coverage | 94.35% | Mutated statements exercised by root tests |
| Fuzzing | 13 targets, 2208636 executions | 10 seconds per target |
<!-- testing-metrics:end -->

## Measurement scope and limits

The [mutation log](performance/mutation.txt), [fuzz log](performance/fuzz.txt) and [combined coverage profile](performance/coverage.txt) support the dated summary above. Their content hashes are recorded in testing-metrics.json. This snapshot is retained evidence, not a measurement of every subsequent edit. Gremlins used two workers and GOMAXPROCS=4. Timeouts do not count as kills; root-test instrumentation does not cover every nested-module and child-process path. Mutation coverage is narrower than combined statement coverage.

The coverage gate measures root-module packages from `go list ./...`, including internal detectors and embargotest. Integration tests contribute coverage for those packages; nested test-tool and adapter modules do not enter the denominator. `scripts/merge_coverage.py --root-module root.cover properties.cover` enforces that scope, and CI requires at least 97%. Neither a coverage percentage nor a mutation score proves that arbitrary secrets cannot leak.

Use `scripts/mutation_attribution.py --output /tmp/mutation-attribution.json` to replay selected expression changes separately against bitmap, adversarial, snapshot, fuzz seed, model, metamorphic and oracle assertions. The tool first requires every unmodified test group to pass and restores each mutation before the next probe. Equality-boundary changes that cannot alter the externally observable result remain equivalent survivors; focused probes are not a substitute for the scheduled full mutation run.

## Technique scope

Metamorphic relations compare a line with independent clean lines around it, line permutations, separate and combined kind selections, percent-encoded email spans, repeated masking, compact and pretty JSON, and real slog output. These catch transformations that break consistency even when each individual output looks plausible. The generated independent lines avoid cross-record context: raw Scan uses bounded context windows that may cross a newline, so a keyword in one line and an ambiguous candidate in another are not independent. Inserting a business label inside a line can intentionally change confidence; ScanLines provides explicit record isolation. Percent decoding is one layer; credential URL grammar retains original delimiters while assignments also use the decoded view. The optional real-log replay uses the checksum-pinned cache and never commits raw log lines. Every line checks padding, idempotence, the union of two disjoint kind sets, and JSON/slog agreement. Email encoding excludes already-percent-escaped lines because the decoder has one layer. The first 64 adjacent pairs per dataset also check permutation with long clean separators that isolate context windows. The held split has been seen and is now regression data, not an independent estimate for new policy decisions.

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
| Logger event snapshots | Valid JSON, no canary/email, retained nested object and array fields | Each adapter test file |
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
