## Public system logs

![Estimated false positives on public logs](images/real-logs.svg)

<!-- real-logs:start -->
| Dataset | Family | Split | Scope | Bytes | Lines | License / source |
|---|---|---|---|---:|---:|---|
| Android | system (LogHub) | development | official 2,000-line sample | 279,076 | 2,000 | [LogHub research/academic use](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/LICENSE); [provenance](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/Android/README.md) |
| Apache | system (LogHub) | development | complete | 5,135,876 | 56,482 | [LogHub research/academic use](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/LICENSE); [provenance](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/Apache/README.md) |
| BGL | system (LogHub) | held | official 2,000-line sample | 317,150 | 2,000 | [LogHub research/academic use](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/LICENSE); [provenance](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/BGL/README.md) |
| HDFS | system (LogHub) | development | official 2,000-line sample | 287,848 | 2,000 | [LogHub research/academic use](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/LICENSE); [provenance](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/HDFS/README.md) |
| Linux | system (LogHub) | development | complete | 2,349,686 | 25,567 | [LogHub research/academic use](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/LICENSE); [provenance](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/Linux/README.md) |
| OpenSSH | system (LogHub) | held | complete | 73,417,506 | 655,147 | [LogHub research/academic use](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/LICENSE); [provenance](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/OpenSSH/README.md) |
| Spark | system (LogHub) | held | official 2,000-line sample | 196,268 | 2,000 | [LogHub research/academic use](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/LICENSE); [provenance](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/Spark/README.md) |
| Zookeeper | system (LogHub) | held | complete | 10,426,438 | 74,380 | [LogHub research/academic use](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/LICENSE); [provenance](https://github.com/logpai/loghub/blob/dd61d0952749ee7963bde24220d1be5ede023033/Zookeeper/README.md) |
| Nginx access | web access | development | complete file | 6,991,577 | 51,462 | [Apache-2.0](https://github.com/elastic/examples/blob/6d86454ebb7a850bcd7e80abe86fe683370018a6/LICENSE); [provenance](https://github.com/elastic/examples/blob/6d86454ebb7a850bcd7e80abe86fe683370018a6/Common%20Data%20Formats/nginx_logs/README.md) |
| Nginx JSON access | web access | development | complete file | 12,137,777 | 51,462 | [Apache-2.0](https://github.com/elastic/examples/blob/6d86454ebb7a850bcd7e80abe86fe683370018a6/LICENSE); [provenance](https://github.com/elastic/examples/blob/6d86454ebb7a850bcd7e80abe86fe683370018a6/Common%20Data%20Formats/nginx_json_logs/README.md) |
| Kubernetes audit | Kubernetes audit | development | complete file | 92,794,383 | 94,287 | [CC-BY-4.0](https://github.com/hkerma/kubernetes-event-dataset/blob/e39cc98e8b27b6862a3f32a85a17565265db36d5/LICENSE.txt); [provenance](https://github.com/hkerma/kubernetes-event-dataset/blob/e39cc98e8b27b6862a3f32a85a17565265db36d5/README.md) |
| CloudTrail ACL | cloud audit | development | complete file | 16,030,714 | 13,274 | [Apache-2.0](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/LICENSE); [provenance](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1562.007/aws_create_acl/aws_create_acl.yml) |
| Apache access | web access | held | complete file | 2,370,789 | 10,000 | [Apache-2.0](https://github.com/elastic/examples/blob/6d86454ebb7a850bcd7e80abe86fe683370018a6/LICENSE); [provenance](https://github.com/elastic/examples/blob/6d86454ebb7a850bcd7e80abe86fe683370018a6/Common%20Data%20Formats/apache_logs/README.md) |
| CloudTrail instances | cloud audit | held | complete file | 16,168,404 | 8,100 | [Apache-2.0](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/LICENSE); [provenance](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/abnormally_high_cloud_instances_launched_old.yml) |
| CloudTrail KMS | cloud audit | held | complete file | 984,076 | 674 | [Apache-2.0](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/LICENSE); [provenance](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1486/aws_kms_key/aws_kms_key.yml) |

15 datasets, 239,887,568 bytes, 1,048,835 lines. Before is the retained baseline aggregate, which covers only the LogHub family; after is the measured current policy, including opt-in country identifiers. The two before/after tables therefore cover LogHub only, and the family table below covers every dataset. The LogHub held split has now been seen and serves as regression data, not an independent evaluation of this change.

Rates below are estimated false-positive findings per decimal GB (10⁹ bytes), not counts of affected lines. IP addresses and published user/contact identities are sensitive references under this evaluation policy; the unspecified listener address 0.0.0.0 is an FP. Checksums do not establish a real account. A hostname fragment is an FP for MyNumber even if the hostname itself identifies a machine.

| Detector | Development before / GB | Development after / GB | Held before / GB | Held after / GB |
|---|---:|---:|---:|---:|
| aba_routing | 1,614.4 | 0.0 | 83.0 | 0.0 |
| ach_trace | 0.0 | 0.0 | 0.0 | 0.0 |
| awskey | 0.0 | 0.0 | 0.0 | 0.0 |
| bank_account | 0.0 | 0.0 | 0.0 | 0.0 |
| br_cnpj | 0.0 | 0.0 | 0.0 | 0.0 |
| br_cpf | 0.0 | 0.0 | 0.0 | 0.0 |
| btc | 0.0 | 0.0 | 0.0 | 0.0 |
| ca_sin | 0.0 | 0.0 | 0.0 | 11.9 |
| card_expiry | 0.0 | 0.0 | 0.0 | 0.0 |
| cn_resident_id | 0.0 | 0.0 | 0.0 | 0.0 |
| credential | 745.1 | 0.0 | 0.0 | 0.0 |
| cvv | 0.0 | 0.0 | 0.0 | 0.0 |
| email | 0.0 | 0.0 | 0.0 | 0.0 |
| eth | 0.0 | 0.0 | 0.0 | 0.0 |
| github_token | 0.0 | 0.0 | 0.0 | 0.0 |
| google_api_key | 0.0 | 0.0 | 0.0 | 0.0 |
| high_entropy | 31,294.7 | 0.0 | 248.9 | 0.0 |
| iban | 0.0 | 0.0 | 0.0 | 0.0 |
| in_aadhaar | 0.0 | 0.0 | 0.0 | 0.0 |
| in_pan | 0.0 | 0.0 | 0.0 | 0.0 |
| ipaddr | 0.0 | 0.0 | 144,062.1 | 0.0 |
| jwt | 0.0 | 0.0 | 0.0 | 0.0 |
| kr_rrn | 0.0 | 0.0 | 0.0 | 0.0 |
| merchant_id | 0.0 | 0.0 | 0.0 | 0.0 |
| mynumber | 8,072.0 | 0.0 | 912.8 | 0.0 |
| pan | 44,209.9 | 0.0 | 0.0 | 0.0 |
| payment_token | 0.0 | 0.0 | 0.0 | 0.0 |
| phone | 0.0 | 0.0 | 0.0 | 0.0 |
| phone_jp | 2,607.9 | 0.0 | 0.0 | 0.0 |
| phone_us | 0.0 | 0.0 | 0.0 | 0.0 |
| private_key_pem | 0.0 | 0.0 | 0.0 | 0.0 |
| service_token | 0.0 | 0.0 | 0.0 | 0.0 |
| slack_token | 0.0 | 0.0 | 0.0 | 0.0 |
| swiftbic | 739,274.8 | 0.0 | 343.8 | 0.0 |
| uk_nhs | 0.0 | 0.0 | 0.0 | 0.0 |
| uk_nino | 0.0 | 0.0 | 0.0 | 0.0 |
| uk_sortcode | 0.0 | 0.0 | 0.0 | 0.0 |
| us_itin | 0.0 | 0.0 | 0.0 | 0.0 |
| us_ssn | 0.0 | 0.0 | 0.0 | 0.0 |

| Configuration | Development before / GB | Development after / GB | Held before / GB | Held after / GB |
|---|---:|---:|---:|---:|
| WithAll | 827,818.9 | 0.0 | 145,650.6 | 11.9 |
| Default slog handler | 827,818.9 | 0.0 | 145,650.6 | 0.0 |
| kinds1 | 0.0 | 0.0 | 0.0 | 0.0 |
| kinds3 | 44,955.1 | 0.0 | 0.0 | 0.0 |
| kinds8 | 47,563.0 | 0.0 | 144,062.1 | 0.0 |

The handler receives each raw line as its message and no attributes; its encoded message is checked against the scanner mask after JSON UTF-8 replacement. These numbers do not measure application-specific field-key policies. All 37 detectors also run separately, with exact findings compared to WithAll.

- kinds1: email.
- kinds3: email, pan, credential.
- kinds8: email, pan, credential, phone_jp, ipaddr, github_token, service_token, private_key_pem.

The operations-log families were added after the LogHub baseline, so they have current rates only. Their split was frozen by source before any finding was inspected: Nginx access, Nginx JSON access, Kubernetes audit and CloudTrail ACL are development; Apache access, CloudTrail instances and CloudTrail KMS are held. The CloudTrail files come from an attack-simulation corpus with placeholder account IDs, and the Kubernetes audit log from a research cluster, so they show log shapes rather than production traffic. The UUID-group and this-network IPv4 rules were chosen from development findings; held samples were labeled after the same review pass and were not used to choose rules, but they have been seen and are not an untouched evaluation.

| Family | Split | Datasets | Bytes | WithAll FP / GB | Default FP / GB | Kinds with sampled FPs |
|---|---|---:|---:|---:|---:|---|
| system (LogHub) | development | 4 | 8,052,486 | 0.0 | 0.0 | none |
| system (LogHub) | held | 4 | 84,357,362 | 11.9 | 0.0 | ca_sin |
| web access | development | 2 | 19,129,354 | 0.0 | 0.0 | none |
| web access | held | 1 | 2,370,789 | 65,379.1 | 0.0 | high_entropy, swiftbic |
| Kubernetes audit | development | 1 | 92,794,383 | 0.0 | 0.0 | none |
| cloud audit | development | 1 | 16,030,714 | 0.0 | 0.0 | none |
| cloud audit | held | 2 | 17,152,480 | 3,672.9 | 116.6 | credential, high_entropy |

Each dataset/kind stratum uses the 40 lowest SHA-256 finding IDs, or every finding if there are fewer. Review labels are in [real-logs-labels.json](real-logs-labels.json); counts and sampled FP fractions are in [real-logs-summary.json](real-logs-summary.json). The estimate sums count × sampled FP fraction across datasets. Zero observed sample FPs does not establish zero population FPs. Small samples, repeated templates and this 239.9 MB source mix cannot predict a deployment’s rate. No recall estimate is possible without labeling undetected secrets.
<!-- real-logs:end -->

The split and download checksums were fixed before held-out results were inspected. Apache, Linux, Android and HDFS supplied development examples; OpenSSH, ZooKeeper, BGL and Spark formed the original held partition. The partition label is retained for comparison; its already-inspected contents are regression data. Four sources are complete datasets and four are LogHub's official 2,000-line samples. LogHub permits research and academic use with attribution and a retained license notice; its license is not the license of the software producing the logs. This study uses the datasets under that research permission and distributes only aggregates and hash-addressed review labels. Downloads, the license notice and sampled excerpts stay outside this repository.

Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu and Michael R. Lyu, [Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics](https://arxiv.org/abs/2008.06448), ISSRE 2023. HDFS provenance also credits Xu et al., SOSP 2009; BGL credits Oliner and Stearley, DSN 2007, as linked in the manifest.

The operations-log family adds shapes LogHub lacks: combined-format and JSON web access logs from [elastic/examples](https://github.com/elastic/examples) (Apache-2.0), a Kubernetes API server audit log from [hkerma/kubernetes-event-dataset](https://github.com/hkerma/kubernetes-event-dataset) (CC-BY-4.0), and AWS CloudTrail events from [splunk/attack_data](https://github.com/splunk/attack_data) (Apache-2.0). Each file is pinned to a commit and a SHA-256 in the manifest. The Kubernetes log accompanies H. Kermabon-Bobinnec et al., [PerfSPEC: Performance Profiling-based Proactive Security Policy Enforcement for Containers](https://doi.org/10.1109/TDSC.2024.3420712), IEEE Transactions on Dependable and Secure Computing. Like the LogHub files, these downloads and their license files stay in the external cache.

Run `make real-log-accuracy LOG_CACHE=/path/outside/the/repository` to verify cached checksums, fetch missing pinned files, scan them and regenerate the table and figure. A new sample ID requires review in `doc/real-logs-labels.json`; the generator never guesses labels. CI runs `python3 scripts/real_logs.py --check` against committed aggregates, source fingerprints and labels without downloading logs.

Classification is kind-specific: an actual contact or network endpoint is a sensitive reference even when published intentionally, while a block ID is not a payment card and a pathname is not an entropy token. The wildcard listener address is valid IP syntax but not a private endpoint, so it counts as an FP for this privacy policy. LogHub logs do not establish that any credential is active, and no authentication was attempted. Uncertain cases must remain unclassified until reviewed rather than being silently counted as true negatives.

The generated table above is the source for current per-kind rates, and the accuracy page includes the same generated evidence. The held partition has now informed the register-slot, invalid-user, identifier, hardware-warning, exception-counter and log-sequence regression rules. These seen logs cannot establish rates on unseen deployments. Path filtering can miss secrets in filenames; version labels can hide real IP addresses, and an unquoted Java object-reference shape under token can hide a real credential. Quoted tokens and password/secret fields retain credential masking.

## Your application logs

The public estimates measure this corpus and labeling policy. Use the [local audit command and diagnostic-preservation recipes](audit.md) on your own logs, then label findings and missed secrets. No root scanner API was added for per-field exemptions or per-Kind thresholds.
