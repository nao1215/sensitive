# Repository policies

This inventory states the owner's active maintenance policy and maps each rule to an executable check. Public source documents and the restated repository policy are sufficient to run CI without private work reports.

<!-- policy-map:start -->
| Rule | Source | Check | Where it runs |
|---|---|---|---|
| Root has no requirements; tools use separate modules | AGENTS.md | [root-module](../scripts/check_policies.py) | Verification |
| Architecture and package inventory remain explicit | AGENTS.md | [TestProductionPackageInventory](../tests/contracts/policy_test.go) | MultiPlatformUnitTest |
| Runtime cannot import test helpers or detector internals | Repository maintenance policy | [edges](../scripts/check_lint_contracts.py) | golangci-lint |
| Secrets have no runtime dependencies or implicit SQL output | Repository maintenance policy | [TestSecretFilesHaveNoRuntimeDependencies](../tests/contracts/policy_test.go) | MultiPlatformUnitTest |
| No struct-tag masking API; Reveal stays explicit | Repository maintenance policy | [api-boundary](../scripts/check_policies.py) | Verification |
| No globals; check errors; use typed error comparisons | AGENTS.md | [lint-config](../scripts/check_policies.py) | Verification |
| Constructor fields and receiver exceptions stay narrow | Repository maintenance policy | [addedContractField](../scripts/check_lint_contracts.py) | golangci-lint |
| Printing exceptions apply only to runnable Examples | Repository maintenance policy | [TestUncheckedPrintingIsOnlyInExamples](../tests/contracts/policy_test.go) | MultiPlatformUnitTest |
| Exported declarations and fields have useful English godoc | AGENTS.md | [godoc](../scripts/check_prose.py) | Verification |
| Runtime public API has runnable godoc Examples | AGENTS.md | [TestExamplesAppearInGodoc](../doc_test.go) | MultiPlatformUnitTest |
| README Go blocks equal runnable public Examples | Repository maintenance policy | [TestReadmeExamples](../doc_test.go) | MultiPlatformUnitTest |
| Examples avoid private imports | Repository maintenance policy | [TestPublicExamplesOnlyImportPublicPackages](../doc_test.go) | MultiPlatformUnitTest |
| API signatures and constant values require review | Repository maintenance policy | [TestAPIGoldenIncludesConstantValues](../tests/contracts/api_test.go) | MultiPlatformUnitTest |
| Prose avoids filler, bold, emoji and wrapped paragraphs | Repository maintenance policy | [markdown](../scripts/check_prose.py) | Verification |
| Godoc varies its openings and avoids repeated benchmark claims | Repository maintenance policy | [repeated-sentence](../scripts/check_prose.py) | Verification |
| Tables fit a 120-character cell budget with reasoned exceptions | Repository maintenance policy | [table](../scripts/check_prose.py) | Verification |
| Badge set, order, centered logo and sponsor link stay intact | AGENTS.md | [branding](../scripts/check_policies.py) | Verification |
| Root coverage is at least 97%; child modules are excluded | Repository maintenance policy | [acceptable: 97%](../.octocov.yml) | Coverage |
| Tests run on three OSes and minimum/stable Go | AGENTS.md | [macos-latest](../.github/workflows/unit_test.yml) | MultiPlatformUnitTest |
| BSD builds remain; unknown paths run full CI | Repository maintenance policy | [class](../scripts/test_ci_changes.py) | MultiPlatformUnitTest |
| State failures clear Input and retain Secret snapshots | Repository maintenance policy | [TestQuintInputReplay](../tests/properties_test.go) | Verification |
| Recorder requires observed bytes and checked expectations | Repository maintenance policy | [TestQuintRecorderReplay](../embargotest/recorder_test.go) | Verification |
| Guard shares limits and replays only safe complete streams | Repository maintenance policy | [TestQuintGuardReplay](../embargotest/guard_test.go) | Verification |
| Recorder cannot start detached goroutines | Repository maintenance policy | [TestRecorderDoesNotStartDetachedGoroutines](../tests/contracts/policy_test.go) | MultiPlatformUnitTest |
| Slog failures emit safe diagnostics and fixed errors | Repository maintenance policy | [TestSlogSuppressesNormalizationFailures](../slog_handler_test.go) | MultiPlatformUnitTest |
| Structured masking preserves shape and bounds its work | Repository maintenance policy | [TestMaskJSONFailureBounds](../json_test.go) | MultiPlatformUnitTest |
| HTTP interim responses share the retention budget | Repository maintenance policy | [TestInformationalHeadersConsumeTotalBudget](../embargotest/detector_test.go) | MultiPlatformUnitTest |
| Hint dispatch agrees with exhaustive scanning | AGENTS.md | [TestDispatchDifferential](../scanner_dispatch_test.go) | MultiPlatformUnitTest |
| Clean scanning retains deterministic allocation gates | AGENTS.md | [TestCleanScanAllocationBudget](../scanner_dispatch_test.go) | MultiPlatformUnitTest |
| Full-width numeric positions map to original bytes | AGENTS.md | [TestNormalizationIdentityDifferential](../internal/detect/fullwidth_test.go) | MultiPlatformUnitTest |
| Confidence is a score; business labels keep lower-confidence findings | Repository maintenance policy | [TestBusinessLabelsAtFieldBoundaries](../internal/detect/label_test.go) | MultiPlatformUnitTest |
| IP unspecified and loopback addresses are excluded | Repository maintenance policy | [Test](../internal/detect/ipaddr_test.go) | MultiPlatformUnitTest |
| Adapters stay isolated and work without local replace directives | Repository maintenance policy | [replace](../scripts/check_adapter_dependencies.py) | MultiPlatformUnitTest |
| Generated documents have semantic and staleness checks | Repository maintenance policy | [class](../scripts/test_doc_figures.py) | MultiPlatformUnitTest |
| Synthetic corpus is deterministic and exact-span scored | Repository maintenance policy | [TestAccuracyRequiresExactUnusedSpans](../tests/accuracy_test.go) | MultiPlatformUnitTest |
| Real logs are checksum-pinned and raw bytes stay out of Git | Repository maintenance policy | [class](../scripts/test_real_logs.py) | MultiPlatformUnitTest |
| Held data seen during fixes is disclosed | Repository maintenance policy | [held-split](../scripts/check_policies.py) | Verification |
| Every listed technique has tests and a CI job | Repository maintenance policy | [technique-links](../scripts/check_policies.py) | Verification |
| Every rule has an implementation and a CI mapping | Repository maintenance policy | [mapping](../scripts/check_policies.py) | Verification |
| Fuzz search and mutation are scheduled; PRs run seeds | Repository maintenance policy | [schedules](../scripts/check_policies.py) | Verification |
| Quint traces and Lean vectors cannot silently drift | Repository maintenance policy | [lake](../scripts/check_lean.py) | Verification |
| External oracles use a pinned offline distribution | Repository maintenance policy | [sha256](../tests/oracles/validate.py) | Verification |
| Benchmarks alternate base and head on one runner | Repository maintenance policy | [order](../scripts/ci_benchmark.py) | Verification |
| Every PR records workflow and job timings in its body | Repository maintenance policy | [ci-timing](../scripts/check_policies.py) | Verification |
| Actions use full SHA pins and explicit least privileges | Repository maintenance policy | [workflow-security](../scripts/check_policies.py) | Verification |
| Lockfile freshness and remote action provenance are checked | Repository maintenance policy | [gh actions-lock --verify](../.github/workflows/verification.yml) | Verification |
| Lockfile keys match the full-SHA workflow references exactly | Repository maintenance policy | [check_exact_refs](../scripts/lock_actions.py) | Verification |
| Vulnerability scans and CodeQL retain scheduled/PR coverage | Repository maintenance policy | [security-scans](../scripts/check_policies.py) | Verification |
| PR titles are English Conventional Commits without agent trailers | Repository maintenance policy | [pr-metadata](../scripts/check_policies.py) | Verification |
| Squash only the owned PR after green CI and resolved review | Repository maintenance policy | [check_merge](../scripts/check_merge.py) | Pre-merge audit |
| No force push or third-party mutations; release only when requested | Repository maintenance policy | [owned_repository](../scripts/check_merge.py) | Pre-merge audit |
| Production fixes retain failing-first evidence | AGENTS.md | [regression-evidence](../scripts/check_policies.py) | Verification |
| Guard diagnostics validate names and track active tests | Repository maintenance policy | [TestGuardNamesAtLeak](../embargotest/guard_names_test.go) | MultiPlatformUnitTest |
| Critical recall cannot drop or retain unmasked expected bytes | Repository maintenance policy | [TestSeverityAccuracy](../tests/severity_test.go) | MultiPlatformUnitTest |
| README techniques link bug classes to individual sections | Repository maintenance policy | [test_readme_links_each_bug_to_its_section](../scripts/test_testing_techniques.py) | Verification |
| Module downloads retry without retrying failed tests | Repository maintenance policy | [test_persistent_failure_is_not_swallowed](../scripts/test_download_modules.py) | Verification |
| Quint npm bumps must match the pinned release evaluator | Repository maintenance policy | [test_changed_expected_version_fails_before_cached_install](../scripts/test_install_quint_evaluator.py) | Verification |
| Production SDK hooks retain real-library integration tests | Repository maintenance policy | [test_sdk_modules_keep_unit_lint_security_and_dependency_checks](../scripts/test_production_hooks.py) | Verification |
| Country corpora are frozen before implementation and remain reproducible | Repository maintenance policy | [test_frozen_corpus_still_matches_definition](../scripts/test_countries.py) | Verification |
| Country checksum references are compiled and compared with Go | Repository maintenance policy | [TestLeanReferenceVectors](../tests/oracles_test.go) | Verification |
| Country precision and residual exposure stay exact-span scored | Repository maintenance policy | [TestCountryAccuracy](../tests/accuracy_test.go) | MultiPlatformUnitTest |
| New hooks keep allocation budgets and scheduled scaling measurements | Repository maintenance policy | [test_hook_scaling_is_scheduled_for_each_new_module](../scripts/test_production_hooks.py) | Verification |
| Encoding limits have one current-behavior regression per disguise | Repository maintenance policy | [TestAdversarialEncodingBoundary](../json_test.go) | MultiPlatformUnitTest |
| Country documentation generation uses UTF-8 independently of the host locale | Repository maintenance policy | [test_country_docs_under_ascii_locale](../scripts/test_countries.py) | Verification |
| Mutation workers and per-test CPUs stay capped at two | Repository maintenance policy | [test_mutation_target_limits_workers_and_test_cpus](../scripts/test_production_hooks.py) | Verification |
| Every Kind documents matching, validation, scores and default selection | Repository maintenance policy | [kind-contract](../scripts/check_prose.py) | Verification |
| README detector rows come from godoc and cannot be missing or stale | Repository maintenance policy | [TestReadmeFreshness](../tests/cmd/detectordocs/main_test.go) | Verification |
| Documented detector scores agree with representative public scans | Repository maintenance policy | [TestKindConfidenceScores](../tests/cmd/detectordocs/main_test.go) | Verification |
| README detector defaults agree with NewScanner behavior | Repository maintenance policy | [TestReadmeDefaults](../tests/cmd/detectordocs/main_test.go) | Verification |
| Detector documentation checks stay wired into CI | Repository maintenance policy | [detector_docs](../scripts/check_policies.py) | Verification |
| Logger scalar masking agrees with original-key JSON context | Repository maintenance policy | [TestLoggerKeyContextDifferential](../tests/integrations_test.go) | MultiPlatformUnitTest |
| Slog scans both standard handler representations | Repository maintenance policy | [TestSlogEncodedRepresentations](../slog_handler_test.go) | MultiPlatformUnitTest |
| Slog explicit groups and WithGroup share a depth bound | Repository maintenance policy | [TestSlogWithGroupDepth](../slog_handler_test.go) | MultiPlatformUnitTest |
| Every documented Kind score survives its inclusive threshold | Repository maintenance policy | [checkScoreThreshold](../tests/cmd/detectordocs/main_test.go) | Verification |
| Masked-key collisions never restore original telemetry values | Repository maintenance policy | [TestMaskedKeyCollisionNeverRestoresOriginal](../adapters/otel/values_test.go) | MultiPlatformUnitTest |
| Log masking retains dropped counts and metadata | Repository maintenance policy | [TestLogPreservesDroppedAttributesAndMetadata](../adapters/otel/log_test.go) | MultiPlatformUnitTest |
| Span masking retains all telemetry counters | Repository maintenance policy | [TestSpanPreservesTelemetryCounters](../adapters/otel/span_test.go) | MultiPlatformUnitTest |
| Context cancellation stops subsequent detectors and raw output | Repository maintenance policy | [TestMaskJSONContextStopsBetweenDetectors](../json_test.go) | MultiPlatformUnitTest |
| Every logger handles colliding masked keys without original values | Repository maintenance policy | [TestLoggerMaskedKeyCollisions](../tests/integrations_test.go) | MultiPlatformUnitTest |
| README-linked examples run alone without private helper files | Repository maintenance policy | [TestReadmeLinkedExamplesStandalone](../doc_test.go) | MultiPlatformUnitTest |
| Documentation distinguishes default kinds and raw credential keys | Repository maintenance policy | [TestDefaultPolicyDocumentation](../doc_test.go) | MultiPlatformUnitTest |
| Standalone-example checks reject missing helper definitions | Repository maintenance policy | [TestStandaloneExamplesRejectMissingHelpers](../doc_test.go) | MultiPlatformUnitTest |
| Logrus Entry.Context cancels formatting and subsequent detector work | Repository maintenance policy | [TestEntryContextCancellation](../adapters/logrus/adapter_test.go) | MultiPlatformUnitTest |
| Adoption cases exercise real outputs and retain declared-policy controls | Repository maintenance policy | [TestAdoptionDeclaredControls](../tests/cases_test.go) | MultiPlatformUnitTest |
| Adoption table is generated from executed cases and checked in CI | Repository maintenance policy | [main](../scripts/case_docs.py) | Verification |
| Output cases isolate detector decisions from canary and fragment matching | Repository maintenance policy | [TestAdoptionCheckIndependence](../tests/cases_test.go) | Verification |
| Canary fragments retain minimum-length and option-order boundaries | Repository maintenance policy | [TestCanaryFragmentBoundsAndOrder](../embargotest/canary_test.go) | MultiPlatformUnitTest |
| Local log audits count actual findings without echoing source values | Repository maintenance policy | [TestReportCountsOffsetsAndNeverEchoesInput](../cmd/embargo/report_test.go) | MultiPlatformUnitTest |
| Diagnostic-preservation recipes retain IDs and expose their recall tradeoff | Repository maintenance policy | [TestAuditDiagnosticRecipe](../tests/cases_test.go) | MultiPlatformUnitTest |
| Detector changes enforce frozen per-Kind accuracy and critical exposure floors | Repository maintenance policy | [TestQualityAccuracy](../tests/quality_gates_test.go) | Verification |
| Real-log gates compare exact sampled FP rates with explicit per-Kind ceilings | Repository maintenance policy | [compare_rates](../scripts/quality_gate.py) | Verification |
| Default-scanner medians fail above twenty percent regression on paired samples | Repository maintenance policy | [default_gate](../scripts/ci_benchmark.py) | Verification |
| Quality jobs use the detector filter and threshold tables cannot silently drift | Repository maintenance policy | [main](../scripts/quality_docs.py) | Verification |
| Tests stay beside sources or in one file per tests-module subject | Repository maintenance policy | [test-file-budget](../scripts/check_policies.py) | Verification |
| Tracked files describe current behavior without development trace labels | Repository maintenance policy | [repository-traces](../scripts/check_policies.py) | Verification |
| Fixed-corpus detection drift requires an Unreleased Detection changes entry | Detection compatibility policy | [def check_change(](../scripts/detection_changes.py) | Verification |
| Every measured library runs every chart scenario and controls remain visible | Comparison policy | [TestComparisonScenarios](../tests/comparison_test.go) | MultiPlatformUnitTest |
| Changed root statements require coverage or a source-bound triage exception | Repository maintenance policy | [def check(](../scripts/diff_coverage.py) | Coverage |
| Mutation package scores and coverage cannot fall below recorded floors | Repository maintenance policy | [def check(](../scripts/mutation_gate.py) | Heavy verification |
| Documented packages and coverage match Go and the coverage gate | AGENTS.md | [documentation-contract](../scripts/check_policies.py) | Verification |
| Growth in large functions requires a reviewed baseline update | AGENTS.md | [function-growth](../scripts/check_policies.py) | Verification |
| One owner each for byte classes, the scanned view and every detector | Repository maintenance policy | [cohesion](../scripts/check_policies.py) | Verification |
<!-- policy-map:end -->

The TDD rule requires a failing regression before a production fix. Record that evidence in the PR or external work report; CI checks that the regression remains. Test readability, useful explanations, false-positive labeling and table layout retain human review alongside executable checks.

Heavy local jobs run serially with GOMAXPROCS at most 4. Every PR changes fewer than 100 files and carries observed workflow/job timings in its body. Preserve the README opening above Quick start. Use English Conventional Commits without agent trailers, squash after green CI, never force push, and do not mutate third-party repositories. Release only when explicitly requested.

Go packages may have one test file per non-test source, plus example_test.go, fuzz_test.go and benchmark_test.go. The tests module uses one file per canonical subject: accuracy, real_logs, comparison, cases, docs, severity, integrations, quality_gates, properties, lifecycle, oracles, api and policy. Command packages retain the source-file rule.

Keep development round labels, finding IDs, numbered decision labels, PR letters, repository PR numbers and repository commit hashes out of tracked text and filenames. CHANGELOG.md retains release references; external dependency and dataset pins retain their provenance. Generators follow the same rule.

## Detection compatibility

A detection change includes adding or removing a default kind, changing a confidence score or threshold, changing the redaction marker or withheld record shape, and adding normalization or decoding. The default minimum confidence is 0. Per-kind thresholds are not supported.

Changes to these observable behaviors require a minor release while the project is below 1.0; a removal or incompatible public API change also requires a minor release. From 1.0, removing a documented detection guarantee, changing defaults or markers, or breaking the withheld record contract requires a major release. Additive opt-in detectors or options require a minor release. A patch may fix an implementation that violates its documented contract, including a security fix, without changing the contract; it must still disclose detection differences.

Every release with a detection change includes a `### Detection changes` heading. During development the entry belongs under `## [Unreleased]`, explains gains and possible false positives or missed values, and names any migration action. Release PRs move those entries into the released section. Security reports and coordinated fixes use [GitHub Security Advisories](https://github.com/nao1215/embargo/security/advisories/new), following [SECURITY.md](../SECURITY.md).

The compatibility gate measures fixed synthetic fixtures and the first 128 lines of each checksum-pinned public log dataset. Only finding locations, kinds, confidence scores and input/masked-output digests are checked in; raw public logs stay in the external cache. `scripts/detection_changes.py --cache CACHE` rejects a stale snapshot and rejects changes from a PR's base unless Unreleased has a nonempty Detection changes entry. `--update` explicitly regenerates the snapshot; it does not waive the release note rule. Existing exact-span accuracy and public-log false-positive gates still apply.

## Unicode separators

Built-in scanners ignore interior non-ASCII characters in Unicode Pd (dash punctuation), Zs (space separators), Cf (format controls), and Sm intersected with the Unicode Dash property (mathematical minus variants). Test generators enumerate the running Go release's tables, so new members are exercised automatically. Numeric normalization also retains the legacy U+30FC prolonged sound mark as a hyphen. Original byte offsets include removed interior formatting runs, including percent-encoded runs.

The allow list is U+0020 SPACE and U+002D HYPHEN-MINUS for fixed-format tokens: these ASCII characters carry ordinary word and token grammar and are not silently removed. Numeric detectors accept their documented space/hyphen separators. Mathematical symbols outside Sm intersected with Dash are operators rather than minus separators and are outside this normalization contract; arbitrary Unicode letters or digits are not transliterated. Leading or trailing formatting marks are preserved because they are outside a token. This normalization may join text that an application intended as separate words; measure the policy on application logs before adoption.
