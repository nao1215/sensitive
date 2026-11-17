# CI execution policy

Keep observed workflow and job timing tables in PR bodies only. Workflow duration runs from creation to the final job completion and includes queue time; job duration runs from started_at to completed_at. Collect timestamps through the GitHub Actions API, identify the compared revisions in the PR and explain relevant changes without claiming that shared-runner noise proves a speedup.

Run heavy local jobs one at a time with GOMAXPROCS at most 4. Mutation testing uses up to four workers with two CPUs each. Minimum and stable Go run on Linux, Windows and macOS; stable legs retain race tests. Coverage combines root and integration instrumentation and enforces the 97% root-module floor. Documentation changes still run policy, generation and prose checks. Fuzzing runs nightly; mutation and scaling run weekly. Keep security scans, dependency provenance checks and formal model/vector checks enabled.

Merge only an owned PR in this repository after required CI is green; use squash merge without force pushes. Each PR changes fewer than 100 files and includes its observed CI timing table. CodeRabbit is best effort. Release publication requires an explicit release request and runs through release.yml after an annotated root version tag.

## Detector quality gates

Accuracy, real-log false positives and paired speed run as three separate Verification jobs when the reusable changes workflow finds production changes in the scanner or its detector dependencies. Documentation, tests, logger wrappers and audit tools alone do not start these jobs. A manual Verification dispatch runs all three so a change to the gates themselves can be tested before merge; set benchmark_base to the intended base commit. Existing allocation contracts, OS tests and security checks remain in their original jobs.

The frozen [threshold file](quality-gates.json) records the v0.5.1 baseline snapshot and SHA-256 hashes of the accuracy, country, credential, severity and real-log inputs. Each of the 37 Kinds has separate development and held thresholds. Precision and recall use exact TP/FP/FN fractions at minimum confidence zero with only the Kind under test enabled; critical Kinds also require zero residual exposed bytes, matching severity.json. The default scanner has a separate speed gate. These are regression budgets on known corpora, including held examples already inspected during earlier fixes, rather than estimates of recall on a new application's logs.

Real-log ceilings use the existing reviewed, stratified sample labels and per-dataset finding counts with all Kinds enabled. Each stratum contributes findings times sampled FP fraction; those estimates are summed and divided by the split's pinned byte count in decimal GB. The gate compares exact rational values, including zero ceilings, without rounding to the displayed table. It verifies checksums after restoring the manifest-keyed cache, scans the current source, and fails on unreviewed sample IDs instead of assigning them a label. Raw logs and sampled values remain in the external cache; artifacts contain aggregate rates only. A zero observed rate is not proof that a Kind never over-masks. For local deployment evidence, use the [audit recipes](audit.md) and review both sensitive and diagnostic fields.

<!-- quality-gates:start -->
| Kind | Development P / R floor (%) | Held P / R floor (%) | Development FP/GB ceiling | Held FP/GB ceiling |
|---|---:|---:|---:|---:|
| aba_routing | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| ach_trace | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| awskey | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| bank_account | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| br_cnpj | 75.00 / 100.00 | 75.00 / 100.00 | 0.000000 | 0.000000 |
| br_cpf | 75.00 / 100.00 | 75.00 / 100.00 | 0.000000 | 0.000000 |
| btc | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| ca_sin | 75.00 / 100.00 | 75.00 / 100.00 | 1862.778774 | 106.688969 |
| card_expiry | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| cn_resident_id | 75.00 / 100.00 | 75.00 / 100.00 | 0.000000 | 0.000000 |
| credential | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| cvv | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| email | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| eth | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| github_token | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| google_api_key | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| high_entropy | 50.00 / 100.00 | 50.00 / 98.33 | 0.000000 | 0.000000 |
| iban | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| in_aadhaar | 75.00 / 100.00 | 75.00 / 100.00 | 0.000000 | 0.000000 |
| in_pan | 75.00 / 100.00 | 75.00 / 100.00 | 0.000000 | 0.000000 |
| ipaddr | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| jwt | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| kr_rrn | 76.92 / 100.00 | 76.92 / 100.00 | 0.000000 | 0.000000 |
| merchant_id | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| mynumber | 81.56 / 100.00 | 81.82 / 100.00 | 0.000000 | 0.000000 |
| pan | 60.08 / 100.00 | 60.00 / 100.00 | 0.000000 | 0.000000 |
| payment_token | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| phone_jp | 82.02 / 100.00 | 81.82 / 100.00 | 0.000000 | 0.000000 |
| private_key_pem | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| service_token | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| slack_token | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| swiftbic | 54.89 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| uk_nhs | 75.00 / 100.00 | 75.00 / 100.00 | 0.000000 | 2287.885674 |
| uk_nino | 75.00 / 100.00 | 75.00 / 100.00 | 0.000000 | 0.000000 |
| uk_sortcode | 100.00 / 100.00 | 100.00 / 100.00 | 0.000000 | 0.000000 |
| us_itin | 75.00 / 100.00 | 75.00 / 100.00 | 0.000000 | 0.000000 |
| us_ssn | 75.00 / 100.00 | 75.00 / 100.00 | 20490.566516 | 379.338557 |
<!-- quality-gates:end -->

P and R mean precision and exact-span recall. Display rounding does not change the committed count fractions or FP/GB rational ceilings. Every built-in Kind, including opt-in Kinds, must have both split entries; a missing entry fails closed.

The speed job builds base and head once, copies the same head-owned default-scanner harness into both archived revisions, and alternates ten 100ms samples in both orders on one runner with GOMAXPROCS=1. Both clean and dirty default-scanner medians must be at most 1.20 times their respective base medians; exactly +20% passes. Missing, nonfinite or nonpositive samples fail. Raw samples, benchstat output, conditions and the machine-readable gate result are retained even on failure. The existing narrowing comparisons remain observations. Shared-runner variation still exists: inspect paired samples when a run fails, and do not retry selectively until a regression disappears.

To run the same gates locally, execute the following commands sequentially with GOMAXPROCS no greater than four. Speed needs two committed revisions because it measures archived source rather than uncommitted edits.

```sh
GOMAXPROCS=4 python3 scripts/quality_gate.py accuracy
GOMAXPROCS=4 python3 scripts/quality_gate.py false-positives --cache "$HOME/.cache/embargo-real-logs"
GOMAXPROCS=4 python3 scripts/ci_benchmark.py --base origin/main --head HEAD
python3 scripts/quality_docs.py --check
```

To raise or lower a precision or recall floor, edit the explicit TP/FP/FN baseline in quality-gates.json in a reviewed PR, regenerate this table with python3 scripts/quality_docs.py, and include labeled examples, previous and proposed ratios, and the reason the changed contract is acceptable. Lowering a floor accepts additional misses or false positives and needs that cost stated explicitly. To tighten or relax an FP ceiling, edit its numerator and denominator with the same evidence and explain the affected diagnostic fields. Never copy new measurement output over the thresholds merely to make CI green; refreshing accuracy or real-log snapshots does not refresh these budgets. The speed policy stays at +20%; changing it requires a separate policy change with paired evidence.

A new detector needs labeled positive and negative examples in both accuracy splits, reviewed real-log sample labels, an explicit precision/recall floor and an initial zero FP/GB ceiling, followed by all three gates. Do not increase a ceiling to hide a new default detector's over-masking. If it exceeds the FP ceiling, keep it opt-in and review a separately documented opt-in ceiling; if it slows the default scanner beyond the speed budget, keep it opt-in. Opt-in status does not bypass the Kind's accuracy or reviewed real-log budget. Existing opt-in Kinds retain their historical nonzero ceilings shown above; the table is a baseline contract, not a recommendation to enable them all.

[Support maintenance](https://github.com/sponsors/nao1215).
