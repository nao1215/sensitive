## Forgotten credentials: independent synthetic corpus

Development seed 120026 and fresh held-out seed 120928 use separate surrounding templates. The initial held-out seed 120927 exposed overlong assignment spans at closing punctuation (227 TP / 133 FP / 133 FN, precision and recall 63.1%). Its templates were then promoted to development; it is not counted as independent final evidence. The replacement set was frozen after that grammar repair and before scoring. The generator does not call embargo, and exact original-byte spans are scored. Each family also sees 120 negatives per category: ordinary prose/IDs, labelled IDs, UUIDs, commit SHAs, URL hashes and public random IDs. No live keys are used. These public samples are no longer unseen data after this round.

<!-- credentials:start -->
| Set | Detector | Threshold | TP | FP | FN | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|---:|
| development | credential | 0.0 | 360 | 0 | 0 | 100.0% | 100.0% |
| development | service_token | 0.0 | 120 | 0 | 0 | 100.0% | 100.0% |
| development | high_entropy | 0.0 | 120 | 120 | 0 | 50.0% | 100.0% |
| development | credential | 0.5 | 360 | 0 | 0 | 100.0% | 100.0% |
| development | service_token | 0.5 | 120 | 0 | 0 | 100.0% | 100.0% |
| development | high_entropy | 0.5 | 0 | 0 | 120 | n/a | 0.0% |
| held | credential | 0.0 | 360 | 0 | 0 | 100.0% | 100.0% |
| held | service_token | 0.0 | 120 | 0 | 0 | 100.0% | 100.0% |
| held | high_entropy | 0.0 | 118 | 118 | 2 | 50.0% | 98.3% |
| held | credential | 0.5 | 360 | 0 | 0 | 100.0% | 100.0% |
| held | service_token | 0.5 | 120 | 0 | 0 | 100.0% | 100.0% |
| held | high_entropy | 0.5 | 0 | 0 | 120 | n/a | 0.0% |
<!-- credentials:end -->

Negative controls are reported by category in the verbose test output. Public random IDs deliberately share the secret distribution. Threshold 0.5 excludes all entropy findings, including true secrets. These synthetic observations do not guarantee production precision.
