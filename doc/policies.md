# Repository policies

The inventory below translates the owner's active repository instructions into checks. Sources are CLAUDE.md, CONTRIBUTING.md, the linked design documents, round reports 2–14 and the owner's master checklist reviewed on 2026-11-16. The reports and checklist live in the owner's private work directory; their decisions are restated here so CI does not require that directory. Later instructions supersede earlier ones: the coverage floor is 97%, the root package layout is internal, and round 15 forbids a release.

<!-- policy-map:start -->
| Rule | Source | Check | Where it runs |
|---|---|---|---|
| Root has no requirements; tools use separate modules | CLAUDE; R6; M14 | [root-module](../scripts/check_policies.py) | Verification |
| Architecture and package inventory remain explicit | CLAUDE; R6 | [TestProductionPackageInventory](../tests/contracts/policy_test.go) | MultiPlatformUnitTest |
| Runtime cannot import test helpers or detector internals | R6; doc/design.md | [edges](../scripts/check_lint_contracts.py) | golangci-lint |
| Secrets have no runtime dependencies or implicit SQL output | R6; R11 | [TestSecretFilesHaveNoRuntimeDependencies](../tests/contracts/policy_test.go) | MultiPlatformUnitTest |
| No struct-tag masking API; Reveal stays explicit | R11; doc/api-review.md | [api-boundary](../scripts/check_policies.py) | Verification |
| No globals; check errors; use typed error comparisons | CLAUDE | [lint-config](../scripts/check_policies.py) | Verification |
| Constructor fields and receiver exceptions stay narrow | R11; R13 | [addedContractField](../scripts/check_lint_contracts.py) | golangci-lint |
| Printing exceptions apply only to runnable Examples | R13 | [TestUncheckedPrintingIsOnlyInExamples](../tests/contracts/example_print_test.go) | MultiPlatformUnitTest |
| Exported declarations and fields have useful English godoc | CLAUDE; M14 | [godoc](../scripts/check_prose.py) | Verification |
| Runtime public API has runnable godoc Examples | CLAUDE; R3; R6 | [TestExamplesAppearInGodoc](../doc_sync_test.go) | MultiPlatformUnitTest |
| README Go blocks equal runnable public Examples | R3; R6 | [TestReadmeExamples](../doc_sync_test.go) | MultiPlatformUnitTest |
| Examples avoid private imports | R6 | [TestPublicExamplesOnlyImportPublicPackages](../doc_sync_test.go) | MultiPlatformUnitTest |
| API signatures and constant values require review | R6; R13 | [TestAPIGoldenIncludesConstantValues](../tests/contracts/api_test.go) | MultiPlatformUnitTest |
| Prose avoids filler, bold, emoji and wrapped paragraphs | R3; R8; M14 | [markdown](../scripts/check_prose.py) | Verification |
| Godoc varies its openings and avoids repeated benchmark claims | M14; R13 | [repeated-sentence](../scripts/check_prose.py) | Verification |
| Tables fit a 120-character cell budget with reasoned exceptions | M14 | [table](../scripts/check_prose.py) | Verification |
| Badge set, order, centered logo and sponsor link stay intact | CLAUDE; R8; R11 | [branding](../scripts/check_policies.py) | Verification |
| Root coverage is at least 97%; child modules are excluded | R13 | [acceptable: 97%](../.octocov.yml) | Coverage |
| Tests run on three OSes and minimum/stable Go | CLAUDE; R6 | [macos-latest](../.github/workflows/unit_test.yml) | MultiPlatformUnitTest |
| BSD builds remain; unknown paths run full CI | R7 | [class](../scripts/test_ci_changes.py) | MultiPlatformUnitTest |
| State failures clear Input and retain Secret snapshots | R11; M14 | [TestQuintInputReplay](../tests/model_input_test.go) | Verification |
| Recorder requires observed bytes and checked expectations | R6; M14 | [TestQuintRecorderReplay](../embargotest/model_replay_test.go) | Verification |
| Guard shares limits and replays only safe complete streams | R12; M14 | [TestQuintGuardReplay](../embargotest/model_replay_test.go) | Verification |
| Recorder cannot start detached goroutines | R6 | [TestRecorderDoesNotStartDetachedGoroutines](../tests/contracts/policy_test.go) | MultiPlatformUnitTest |
| Slog failures suppress output and emit fixed errors | R6; R11 | [TestSlogSuppressesNormalizationFailures](../slog_handler_test.go) | MultiPlatformUnitTest |
| Structured masking preserves shape and bounds its work | R11 | [TestMaskJSONFailureBounds](../structured_test.go) | MultiPlatformUnitTest |
| HTTP interim responses share the retention budget | R6 | [TestInformationalHeadersConsumeTotalBudget](../embargotest/detector_test.go) | MultiPlatformUnitTest |
| Hint dispatch agrees with exhaustive scanning | CLAUDE; R9 | [TestDispatchDifferential](../scanner_dispatch_test.go) | MultiPlatformUnitTest |
| Clean scanning retains deterministic allocation gates | CLAUDE; R9 | [TestCleanScanAllocationBudget](../scanner_dispatch_test.go) | MultiPlatformUnitTest |
| Full-width numeric positions map to original bytes | CLAUDE; R9 | [TestNormalizationIdentityDifferential](../internal/detect/mutation_round9_test.go) | MultiPlatformUnitTest |
| Confidence is a score; business labels keep lower-confidence findings | R9 | [TestBusinessLabelsAtFieldBoundaries](../internal/detect/mutation_round9_test.go) | MultiPlatformUnitTest |
| IP unspecified and loopback addresses are excluded | M14 | [Test](../internal/detect/ip_policy_test.go) | MultiPlatformUnitTest |
| Adapters stay isolated and work without local replace directives | R7; R11 | [replace](../scripts/check_adapter_dependencies.py) | MultiPlatformUnitTest |
| Generated documents have semantic and staleness checks | R3; R9; M14 | [class](../scripts/test_doc_figures.py) | MultiPlatformUnitTest |
| Synthetic corpus is deterministic and exact-span scored | R9; R12 | [TestAccuracyRequiresExactUnusedSpans](../tests/accuracy_test.go) | MultiPlatformUnitTest |
| Real logs are checksum-pinned and raw bytes stay out of Git | R13 | [class](../scripts/test_real_logs.py) | MultiPlatformUnitTest |
| Held data seen during fixes is disclosed | M14 | [held-split](../scripts/check_policies.py) | Verification |
| Every listed technique has tests and a CI job | M14 | [technique-links](../scripts/check_policies.py) | Verification |
| Every rule has an implementation and a CI mapping | M14 | [mapping](../scripts/check_policies.py) | Verification |
| Fuzz search and mutation are scheduled; PRs run seeds | R7; M14 | [schedules](../scripts/check_policies.py) | Verification |
| Quint traces and Lean vectors cannot silently drift | M14 | [lake](../scripts/check_lean.py) | Verification |
| External oracles use a pinned offline distribution | M14 | [sha256](../tests/oracles/validate.py) | Verification |
| Benchmarks alternate base and head on one runner | R6; M14 | [order](../scripts/ci_benchmark.py) | Verification |
| Every round records workflow and job timings | M14 | [ci-timing](../scripts/check_policies.py) | Verification |
| Actions use full SHA pins and explicit least privileges | R11; M14 | [workflow-security](../scripts/check_policies.py) | Verification |
| Lockfile freshness and remote action provenance are checked | M14 | [gh actions-lock --verify](../.github/workflows/verification.yml) | Verification |
| Lockfile keys match the full-SHA workflow references exactly | M14 | [check_exact_refs](../scripts/lock_actions.py) | Verification |
| Vulnerability scans and CodeQL retain scheduled/PR coverage | R7; R11 | [security-scans](../scripts/check_policies.py) | Verification |
| PR titles are English Conventional Commits without agent trailers | R6; M14 | [pr-metadata](../scripts/check_policies.py) | Verification |
| Squash only the owned PR after green CI and resolved review | R6; M14 | [check_merge](../scripts/check_merge.py) | Pre-merge audit |
| No force push, release or third-party mutations in this workflow | M14 | [owned_repository](../scripts/check_merge.py) | Pre-merge audit |
| Production fixes retain failing-first evidence | CLAUDE; M14 | [regression-evidence](../scripts/check_policies.py) | Verification |
| Guard diagnostics validate names and track active tests | M15 | [TestGuardNamesAtLeak](../embargotest/guard_names_test.go) | MultiPlatformUnitTest |
| Critical recall cannot drop or retain unmasked expected bytes | M15 | [TestSeverityAccuracy](../tests/severity_test.go) | MultiPlatformUnitTest |
| README techniques link bug classes to individual sections | M15 | [test_readme_links_each_bug_to_its_section](../scripts/test_testing_techniques.py) | Verification |
| Module downloads retry without retrying failed tests | M15 | [test_persistent_failure_is_not_swallowed](../scripts/test_download_modules.py) | Verification |
| Quint npm bumps must match the pinned release evaluator | M15 | [test_changed_expected_version_fails_before_cached_install](../scripts/test_install_quint_evaluator.py) | Verification |
| Production SDK hooks retain real-library integration tests | M15 | [test_sdk_modules_keep_unit_lint_security_and_dependency_checks](../scripts/test_production_hooks.py) | Verification |
| Country corpora are frozen before implementation and remain reproducible | M15 | [test_frozen_corpus_still_matches_definition](../scripts/test_countries.py) | Verification |
| Country checksum references are compiled and compared with Go | M15 | [TestLeanReferenceVectors](../tests/lean_vectors_test.go) | Verification |
| Country precision and residual exposure stay exact-span scored | M15 | [TestCountryAccuracy](../tests/countries_accuracy_test.go) | MultiPlatformUnitTest |
| New hooks keep allocation budgets and scheduled scaling measurements | M15 | [test_hook_scaling_is_scheduled_for_each_new_module](../scripts/test_production_hooks.py) | Verification |
| Encoding limits have one current-behavior regression per disguise | M15 | [TestAdversarialEncodingBoundary](../adversarial_test.go) | MultiPlatformUnitTest |
| Country documentation generation uses UTF-8 independently of the host locale | M15; PR88 review | [test_country_docs_under_ascii_locale](../scripts/test_countries.py) | Verification |
| Mutation workers and per-test CPUs stay capped at two | M15 | [test_mutation_target_limits_workers_and_test_cpus](../scripts/test_production_hooks.py) | Verification |
| Every Kind documents matching, validation, scores and default selection | M16 | [kind-contract](../scripts/check_prose.py) | Verification |
| README detector rows come from godoc and cannot be missing or stale | M16 | [TestReadmeFreshness](../tests/cmd/detectordocs/main_test.go) | Verification |
| Documented detector scores agree with representative public scans | M16 | [TestKindConfidenceScores](../tests/cmd/detectordocs/scores_test.go) | Verification |
| README detector defaults agree with NewScanner behavior | M16 | [TestReadmeDefaults](../tests/cmd/detectordocs/scores_test.go) | Verification |
| Detector documentation checks stay wired into CI | M16 | [detector_docs](../scripts/check_policies.py) | Verification |
| Logger scalar masking agrees with original-key JSON context | M19 | [TestLoggerKeyContextDifferential](../tests/slog_handler_test.go) | MultiPlatformUnitTest |
| Slog scans both standard handler representations | M19 | [TestSlogEncodedRepresentations](../slog_handler_test.go) | MultiPlatformUnitTest |
| Slog explicit groups and WithGroup share a depth bound | M19 | [TestSlogWithGroupDepth](../slog_handler_test.go) | MultiPlatformUnitTest |
| Every documented Kind score survives its inclusive threshold | M19 | [checkScoreThreshold](../tests/cmd/detectordocs/scores_test.go) | Verification |
| Masked-key collisions never restore original telemetry values | M19 | [TestMaskedKeyCollisionNeverRestoresOriginal](../adapters/otel/values_test.go) | MultiPlatformUnitTest |
| Log masking retains dropped counts and metadata | M19 | [TestLogPreservesDroppedAttributesAndMetadata](../adapters/otel/log_test.go) | MultiPlatformUnitTest |
| Span masking retains all telemetry counters | M19 | [TestSpanPreservesTelemetryCounters](../adapters/otel/span_test.go) | MultiPlatformUnitTest |
| Context cancellation stops subsequent detectors and output | M19 | [TestMaskJSONContextStopsBetweenDetectors](../structured_test.go) | MultiPlatformUnitTest |
| Every logger handles colliding masked keys without original values | M19 | [TestLoggerMaskedKeyCollisions](../tests/slog_handler_test.go) | MultiPlatformUnitTest |
| README-linked examples run alone without private helper files | M19 | [TestReadmeLinkedExamplesStandalone](../doc_sync_test.go) | MultiPlatformUnitTest |
| Documentation distinguishes default kinds and raw credential keys | M19 | [TestDefaultPolicyDocumentation](../doc_sync_test.go) | MultiPlatformUnitTest |
| Standalone-example checks reject missing helper definitions | M19 | [TestStandaloneExamplesRejectMissingHelpers](../doc_sync_test.go) | MultiPlatformUnitTest |
| Logrus Entry.Context cancels formatting and subsequent detector work | M19 | [TestEntryContextCancellation](../adapters/logrus/adapter_test.go) | MultiPlatformUnitTest |
| Adoption cases exercise real outputs and retain declared-policy controls | M21 | [TestAdoptionDeclaredControls](../tests/adoption_cases_test.go) | MultiPlatformUnitTest |
| Adoption table is generated from executed cases and checked in CI | M21 | [main](../scripts/case_docs.py) | Verification |
| Output cases isolate detector decisions from canary and fragment matching | M21 | [TestAdoptionCheckIndependence](../tests/check_independence_test.go) | Verification |
| Canary fragments retain minimum-length and option-order boundaries | M21 | [TestCanaryFragmentBoundsAndOrder](../embargotest/canary_fragment_test.go) | MultiPlatformUnitTest |
| Local log audits count actual findings without echoing source values | M21 | [TestAuditCountsOffsetsAndNeverEchoesInput](../tests/cmd/embargo-audit/main_test.go) | MultiPlatformUnitTest |
| Diagnostic-preservation recipes retain IDs and expose their recall tradeoff | M21 | [TestAuditDiagnosticRecipe](../tests/audit_recipes_test.go) | MultiPlatformUnitTest |
| Detector changes enforce frozen per-Kind accuracy and critical exposure floors | M21 | [TestQualityAccuracy](../tests/quality_accuracy_test.go) | Verification |
| Real-log gates compare exact sampled FP rates with explicit per-Kind ceilings | M21 | [compare_rates](../scripts/quality_gate.py) | Verification |
| Default-scanner medians fail above twenty percent regression on paired samples | M21 | [default_gate](../scripts/ci_benchmark.py) | Verification |
| Quality jobs use the detector filter and threshold tables cannot silently drift | M21 | [main](../scripts/quality_docs.py) | Verification |
<!-- policy-map:end -->

## Changing a rule

Update scripts/policies.json with a concrete check and the workflow that executes it, then run `python3 scripts/check_policies.py --write`. A missing implementation, unknown workflow, absent test path or stale table fails Verification. The rule inventory is reviewed when an owner instruction changes; no parser can infer new instructions from an unstructured conversation. Checks for code and documents run in CI; merge-time checks inspect live GitHub state immediately before the authorized squash merge.

Source labels R2–R14 refer to the corresponding owner round reports; M14 refers to the master checklist and round-14 request. M15 refers to the Round 15 request, including the two-PR split and serial heavy jobs. M16 requires the godoc-derived detector table, measured score contracts and one PR below 100 files; heavy local jobs remain serial with GOMAXPROCS at most 4. Historical release and artwork approvals are not standing permission to publish releases or change artwork. Work on other repositories and future release tags remains outside this round. Round 15 authorizes the specified country detectors and isolated production hooks. Automated checks constrain this repository and its merge command; they cannot audit unrelated commands executed outside the repository.

The TDD rule requires a failing regression before a production fix. The round report records that evidence; CI can verify the regression remains, but cannot reconstruct the order of uncommitted edits. Test readability, useful explanations, false-positive labeling and visual table layout also retain human review alongside the executable checks.

[Support maintenance](https://github.com/sponsors/nao1215).
