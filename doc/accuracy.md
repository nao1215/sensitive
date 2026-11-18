# Synthetic accuracy corpus

## Conditions

The development set uses Python `random.Random(20261115)`; the held-out set uses `random.Random(20270129)` and six different surrounding templates. Original inputs were fixed before detector changes. Added ARN, build-language, SSH-remote and version controls are regression evidence; incomplete PEM expected spans now include the existing suffix through end of input, retaining every previously expected byte. Tuning used development failures and independent code-review regressions; the held-out evaluation rejected a stricter SWIFT context rule because it reduced recall. We treated this as overfitting and reverted the rule; no held-out failure was used to tune the retained changes.

Development contains 16,492 evaluations; held-out contains 16,032. The [generator](../scripts/generate_accuracy.py) constructs values and original byte ranges without invoking embargo. Development includes hand-written controls; held-out includes only independently generated values and controls. Repeated surroundings reuse values, and deterministic format examples such as email names and date cycles occur in both sets. Counts are not independent statistical trials. This is synthetic evaluation, not evidence of production accuracy or credential validity.

Surroundings include logs, JSON, URLs, line endings and Japanese text. Negative controls include hashes, UUIDs, timestamps, order/invoice/tracking identifiers, versions, invalid checksums and malformed credentials. Labels and templates are not a substitute for a real-world corpus.

A hit requires the same kind and exact unused original byte range. Partial, duplicate and extra matches count as false positives; missing expected ranges count as false negatives. Precision is TP/(TP+FP); recall is TP/(TP+FN). Each detector runs alone.

The default minimum confidence remains 0: ambiguous candidates are included. Confidence is a heuristic, not a probability. PAN checksum failures score 0.6; PAN, My Number and Japanese phone candidates with an attached order, invoice, tracking, version, build, serial or shipment label score 0.4. `WithMinConfidence(0.7)` excludes these candidates and can therefore miss genuine secrets under misleading business labels. A global 0.7 threshold also removes the 0.5–0.65 bank-account findings and some sort-code findings; it is not a universal accuracy setting. Both policies are measured below; the detector charts use held-out results at the default threshold.

## Encoding policy

The original 23 built-in detectors decode exactly one layer of valid `%HH` escapes anywhere in the input before detection. Findings map back to original bytes, so masking covers the escaped representation. Literal `+` and malformed percent escapes remain unchanged. Custom detectors receive the original bytes. KindCredential additionally scans up to two Go/JSON quote and backslash escape layers with original byte offsets. One layer of `\u00XX` escapes of ASCII characters, as JSON and Go write them, is decoded first, so `alice\u0040example.com` is an email address. Base64, hexadecimal, HTML entities, escapes of non-ASCII characters and recursively percent-encoded forms are not decoded by Scanner; decode application fields explicitly when needed. The logger adapters separately decode JSON strings at their output boundary. Structured values, from MaskJSON through the slog and HTTP handlers to the adapters, also read a string of 20 bytes to 8 KiB that is padded standard base64 as the bytes it encodes when those bytes are printable UTF-8 text, because encoding/json and zap.Binary write `[]byte` fields that way; binary data is not scanned.

[Round-trip and offset properties](../percent_test.go) exercise random partial escaping and all byte values. [Regression tests](../tests/accuracy_test.go) reject new mismatches and obsolete exceptions in both sets. Known limits retain reasons in [development](../tests/testdata/accuracy_limits.jsonl) and [held-out](../tests/testdata/accuracy_held_limits.jsonl) fixtures.

## Held-out results: default threshold 0

![Held-out precision and recall](images/accuracy.svg)

| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |
|---|---:|---:|---:|---:|
| [aba_routing](#aba-routing) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [ach_trace](#ach-trace) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [awskey](#awskey) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [bank_account](#bank-account) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [btc](#btc) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [card_expiry](#card-expiry) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [cvv](#cvv) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [email](#email) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [eth](#eth) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [github_token](#github-token) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [google_api_key](#google-api-key) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [iban](#iban) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [ipaddr](#ipaddr) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [jwt](#jwt) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [merchant_id](#merchant-id) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [mynumber](#mynumber) | 144 / 544 | 144 / 32 / 0 | 81.8% | 100.0% |
| [pan](#pan) | 144 / 544 | 144 / 96 / 0 | 60.0% | 100.0% |
| [payment_token](#payment-token) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [phone_jp](#phone-jp) | 144 / 544 | 144 / 32 / 0 | 81.8% | 100.0% |
| [phone_us](#phone-us) | 144 / 64 | 144 / 0 / 0 | 100.0% | 100.0% |
| [private_key_pem](#private-key-pem) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [slack_token](#slack-token) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [swiftbic](#swiftbic) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [uk_sortcode](#uk-sortcode) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |

PAN negatives are deliberate card-like look-alikes; public-log PAN FP/GB: 0.0 development, 0.0 held. See [public-log sampling and classification](real-logs.md).

## Development results: default threshold 0

| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |
|---|---:|---:|---:|---:|
| [aba_routing](#aba-routing) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [ach_trace](#ach-trace) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [awskey](#awskey) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [bank_account](#bank-account) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [btc](#btc) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [card_expiry](#card-expiry) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [cvv](#cvv) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [email](#email) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [eth](#eth) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [github_token](#github-token) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [google_api_key](#google-api-key) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [iban](#iban) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [ipaddr](#ipaddr) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [jwt](#jwt) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [merchant_id](#merchant-id) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [mynumber](#mynumber) | 146 / 562 | 146 / 33 / 0 | 81.6% | 100.0% |
| [pan](#pan) | 146 / 562 | 146 / 97 / 0 | 60.1% | 100.0% |
| [payment_token](#payment-token) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [phone_jp](#phone-jp) | 146 / 562 | 146 / 32 / 0 | 82.0% | 100.0% |
| [phone_us](#phone-us) | 144 / 64 | 144 / 0 / 0 | 100.0% | 100.0% |
| [private_key_pem](#private-key-pem) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [slack_token](#slack-token) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [swiftbic](#swiftbic) | 146 / 562 | 146 / 24 / 0 | 85.9% | 100.0% |
| [uk_sortcode](#uk-sortcode) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |

PAN negatives are deliberate card-like look-alikes; public-log PAN FP/GB: 0.0 development, 0.0 held. See [public-log sampling and classification](real-logs.md).

## Held-out results: minimum confidence 0.5

| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |
|---|---:|---:|---:|---:|
| [aba_routing](#aba-routing) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [ach_trace](#ach-trace) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [awskey](#awskey) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [bank_account](#bank-account) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [btc](#btc) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [card_expiry](#card-expiry) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [cvv](#cvv) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [email](#email) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [eth](#eth) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [github_token](#github-token) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [google_api_key](#google-api-key) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [iban](#iban) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [ipaddr](#ipaddr) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [jwt](#jwt) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [merchant_id](#merchant-id) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [mynumber](#mynumber) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [pan](#pan) | 144 / 544 | 144 / 64 / 0 | 69.2% | 100.0% |
| [payment_token](#payment-token) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [phone_jp](#phone-jp) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [phone_us](#phone-us) | 144 / 64 | 144 / 0 / 0 | 100.0% | 100.0% |
| [private_key_pem](#private-key-pem) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [slack_token](#slack-token) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [swiftbic](#swiftbic) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [uk_sortcode](#uk-sortcode) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |

PAN negatives are deliberate card-like look-alikes; public-log PAN FP/GB: 0.0 development, 0.0 held. See [public-log sampling and classification](real-logs.md).

## Development results: minimum confidence 0.5

| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |
|---|---:|---:|---:|---:|
| [aba_routing](#aba-routing) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [ach_trace](#ach-trace) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [awskey](#awskey) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [bank_account](#bank-account) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [btc](#btc) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [card_expiry](#card-expiry) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [cvv](#cvv) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [email](#email) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [eth](#eth) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [github_token](#github-token) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [google_api_key](#google-api-key) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [iban](#iban) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [ipaddr](#ipaddr) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [jwt](#jwt) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [merchant_id](#merchant-id) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [mynumber](#mynumber) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [pan](#pan) | 146 / 562 | 146 / 64 / 0 | 69.5% | 100.0% |
| [payment_token](#payment-token) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [phone_jp](#phone-jp) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [phone_us](#phone-us) | 144 / 64 | 144 / 0 / 0 | 100.0% | 100.0% |
| [private_key_pem](#private-key-pem) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [slack_token](#slack-token) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [swiftbic](#swiftbic) | 146 / 562 | 146 / 24 / 0 | 85.9% | 100.0% |
| [uk_sortcode](#uk-sortcode) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |

PAN negatives are deliberate card-like look-alikes; public-log PAN FP/GB: 0.0 development, 0.0 held. See [public-log sampling and classification](real-logs.md).

## Held-out results: minimum confidence 0.7

| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |
|---|---:|---:|---:|---:|
| [aba_routing](#aba-routing) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [ach_trace](#ach-trace) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [awskey](#awskey) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [bank_account](#bank-account) | 144 / 544 | 0 / 0 / 144 | n/a | 0.0% |
| [btc](#btc) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [card_expiry](#card-expiry) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [cvv](#cvv) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [email](#email) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [eth](#eth) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [github_token](#github-token) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [google_api_key](#google-api-key) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [iban](#iban) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [ipaddr](#ipaddr) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [jwt](#jwt) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [merchant_id](#merchant-id) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [mynumber](#mynumber) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [pan](#pan) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [payment_token](#payment-token) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [phone_jp](#phone-jp) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [phone_us](#phone-us) | 144 / 64 | 144 / 0 / 0 | 100.0% | 100.0% |
| [private_key_pem](#private-key-pem) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [slack_token](#slack-token) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [swiftbic](#swiftbic) | 144 / 544 | 144 / 0 / 0 | 100.0% | 100.0% |
| [uk_sortcode](#uk-sortcode) | 144 / 544 | 132 / 0 / 12 | 100.0% | 91.7% |

PAN negatives are deliberate card-like look-alikes; public-log PAN FP/GB: 0.0 development, 0.0 held. See [public-log sampling and classification](real-logs.md).

## Development results: minimum confidence 0.7

| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |
|---|---:|---:|---:|---:|
| [aba_routing](#aba-routing) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [ach_trace](#ach-trace) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [awskey](#awskey) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [bank_account](#bank-account) | 146 / 562 | 0 / 0 / 146 | n/a | 0.0% |
| [btc](#btc) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [card_expiry](#card-expiry) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [cvv](#cvv) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [email](#email) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [eth](#eth) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [github_token](#github-token) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [google_api_key](#google-api-key) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [iban](#iban) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [ipaddr](#ipaddr) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [jwt](#jwt) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [merchant_id](#merchant-id) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [mynumber](#mynumber) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [pan](#pan) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [payment_token](#payment-token) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [phone_jp](#phone-jp) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [phone_us](#phone-us) | 144 / 64 | 144 / 0 / 0 | 100.0% | 100.0% |
| [private_key_pem](#private-key-pem) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [slack_token](#slack-token) | 146 / 562 | 146 / 0 / 0 | 100.0% | 100.0% |
| [swiftbic](#swiftbic) | 146 / 562 | 146 / 24 / 0 | 85.9% | 100.0% |
| [uk_sortcode](#uk-sortcode) | 146 / 562 | 134 / 0 / 12 | 100.0% | 91.8% |

PAN negatives are deliberate card-like look-alikes; public-log PAN FP/GB: 0.0 development, 0.0 held. See [public-log sampling and classification](real-logs.md).

## aba routing

![Held-out aba_routing precision and recall](images/accuracy-aba_routing.svg)

Verified by the [aba_routing format tests](../internal/detect/aba_test.go) and the [corpus regression check](../tests/accuracy_test.go). Independently generated routing checksums, line endings and checksum failures.

At the default threshold, no misses or false alarms appeared in either set.

## ach trace

![Held-out ach_trace precision and recall](images/accuracy-ach_trace.svg)

Verified by the [ach_trace format tests](../internal/detect/ach_test.go) and the [corpus regression check](../tests/accuracy_test.go). Contextual fifteen-digit traces, line endings and short traces as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## awskey

![Held-out awskey precision and recall](images/accuracy-awskey.svg)

Verified by the [awskey format tests](../internal/detect/awskey_test.go) and the [corpus regression check](../tests/accuracy_test.go). AKIA and ASIA prefixes in log, JSON and Japanese text; short tokens as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## bank account

![Held-out bank_account precision and recall](images/accuracy-bank_account.svg)

Verified by the [bank_account format tests](../internal/detect/bank_account_test.go) and the [corpus regression check](../tests/accuracy_test.go). Contextual account numbers in log, JSON and Japanese text; too-short values as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## btc

![Held-out btc precision and recall](images/accuracy-btc.svg)

Verified by the [btc format tests](../internal/detect/btc_test.go) and the [corpus regression check](../tests/accuracy_test.go). Independently generated Base58Check P2PKH addresses and invalid checksum look-alikes.

At the default threshold, no misses or false alarms appeared in either set.

## card expiry

![Held-out card_expiry precision and recall](images/accuracy-card_expiry.svg)

Verified by the [card_expiry format tests](../internal/detect/card_expiry_test.go) and the [corpus regression check](../tests/accuracy_test.go). Month/year dates near expiry context in log, JSON and Japanese text; invalid months as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## cvv

![Held-out cvv precision and recall](images/accuracy-cvv.svg)

Verified by the [cvv format tests](../internal/detect/cvv_test.go) and the [corpus regression check](../tests/accuracy_test.go). Three-digit values near CVV context in log, JSON and Japanese text; two-digit values as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## email

![Held-out email precision and recall](images/accuracy-email.svg)

Verified by the [email format tests](../internal/detect/email_test.go) and the [corpus regression check](../tests/accuracy_test.go). Plus-addressing, JSON fields, Japanese boundaries and doubled-at-sign negatives.

At the default threshold, no misses or false alarms appeared in either set.

## eth

![Held-out eth precision and recall](images/accuracy-eth.svg)

Verified by the [eth format tests](../internal/detect/eth_test.go) and the [corpus regression check](../tests/accuracy_test.go). Lowercase hexadecimal addresses and malformed non-hexadecimal look-alikes.

At the default threshold, no misses or false alarms appeared in either set.

## github token

![Held-out github_token precision and recall](images/accuracy-github_token.svg)

Verified by the [github_token format tests](../internal/detect/github_token_test.go) and the [corpus regression check](../tests/accuracy_test.go). Four classic token prefixes in log, JSON and Japanese text; short tokens as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## google api key

![Held-out google_api_key precision and recall](images/accuracy-google_api_key.svg)

Verified by the [google_api_key format tests](../internal/detect/google_apikey_test.go) and the [corpus regression check](../tests/accuracy_test.go). AIza-prefixed keys in log, JSON and Japanese text; short bodies as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## iban

![Held-out iban precision and recall](images/accuracy-iban.svg)

Verified by the [iban format tests](../internal/detect/iban_test.go) and the [corpus regression check](../tests/accuracy_test.go). Independently generated German MOD 97 check digits and surrounding JSON or log text.

At the default threshold, no misses or false alarms appeared in either set.

## ipaddr

![Held-out ipaddr precision and recall](images/accuracy-ipaddr.svg)

Verified by the [ipaddr format tests](../internal/detect/ipaddr_test.go) and the [corpus regression check](../tests/accuracy_test.go). Documentation-range IPv4 and IPv6 addresses, Japanese boundaries and invalid octets.

At the default threshold, no misses or false alarms appeared in either set.

## jwt

![Held-out jwt precision and recall](images/accuracy-jwt.svg)

Verified by the [jwt format tests](../internal/detect/jwt_test.go) and the [corpus regression check](../tests/accuracy_test.go). Base64url header, payload and signature fields; malformed payload look-alikes.

At the default threshold, no misses or false alarms appeared in either set.

## merchant id

![Held-out merchant_id precision and recall](images/accuracy-merchant_id.svg)

Verified by the [merchant_id format tests](../internal/detect/merchant_id_test.go) and the [corpus regression check](../tests/accuracy_test.go). Contextual merchant IDs in log, JSON and Japanese text; short IDs as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## mynumber

![Held-out mynumber precision and recall](images/accuracy-mynumber.svg)

Verified by the [mynumber format tests](../internal/detect/mynumber_test.go) and the [corpus regression check](../tests/accuracy_test.go). Independently generated MOD 11 check digits, full-width digits and Japanese text boundaries.

| Set / observed limit | Input example | Why it remains |
|---|---|---|
| development: `mynumber/control/invoice/0` | `Invoice: 004254390645` | Explanation 1 below. |

1. Business identifiers can satisfy sensitive-number shapes and checksums. Attached business labels lower confidence to 0.4, but the default threshold of 0 preserves ambiguous candidates.

## pan

![Held-out pan precision and recall](images/accuracy-pan.svg)

Verified by the [pan format tests](../internal/detect/pan_test.go) and the [corpus regression check](../tests/accuracy_test.go). Luhn-valid Visa, Mastercard, Amex and JCB shapes, hyphen-separated groups and full-width digits.

| Set / observed limit | Input example | Why it remains |
|---|---|---|
| development: `pan/control/order/0` | `Order ID: 4327088982216106` | Explanation 1 below. |
| development: `pan/negative/0/japanese` | `処理結果【card-like 4865015899549583】を記録しました` | Explanation 2 below. |

1. Business identifiers can satisfy sensitive-number shapes and checksums. Attached business labels lower confidence to 0.4, but the default threshold of 0 preserves ambiguous candidates.

2. PAN deliberately returns BIN/length candidates with a failing Luhn checksum at lower confidence; default confidence accepts them.

## payment token

![Held-out payment_token precision and recall](images/accuracy-payment_token.svg)

Verified by the [payment_token format tests](../internal/detect/payment_token_test.go) and the [corpus regression check](../tests/accuracy_test.go). Five payment-token prefixes in log, JSON and Japanese text; short bodies as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## phone jp

![Held-out phone_jp precision and recall](images/accuracy-phone_jp.svg)

Verified by the [phone_jp format tests](../internal/detect/phone_jp_test.go) and the [corpus regression check](../tests/accuracy_test.go). Hyphenated mobile numbers, full-width digits and Japanese text boundaries.

| Set / observed limit | Input example | Why it remains |
|---|---|---|
| development: `phone_jp/control/phone-shaped serial/0` | `Serial: 090-1000-2000` | Explanation 1 below. |

1. Business identifiers can satisfy sensitive-number shapes and checksums. Attached business labels lower confidence to 0.4, but the default threshold of 0 preserves ambiguous candidates.

## phone us

![Held-out phone_us precision and recall](images/accuracy-phone_us.svg)

Verified by the [phone_us format tests](../internal/detect/phone_us_test.go) and the [corpus regression check](../tests/accuracy_test.go). Hyphenated, dotted and parenthesized fictional 555-01xx numbers.

At the default threshold, no misses or false alarms appeared in either set.

## private key pem

![Held-out private_key_pem precision and recall](images/accuracy-private_key_pem.svg)

Verified by the [private_key_pem format tests](../internal/detect/private_key_pem_test.go) and the [corpus regression check](../tests/accuracy_test.go). RSA, EC, OpenSSH and PKCS#8 private-key headers; public-key and certificate headers as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## slack token

![Held-out slack_token precision and recall](images/accuracy-slack_token.svg)

Verified by the [slack_token format tests](../internal/detect/slack_token_test.go) and the [corpus regression check](../tests/accuracy_test.go). Multi-part xoxb shapes in log, JSON and Japanese text; an unsupported type letter as a negative.

At the default threshold, no misses or false alarms appeared in either set.

## swiftbic

![Held-out swiftbic precision and recall](images/accuracy-swiftbic.svg)

Verified by the [swiftbic format tests](../internal/detect/swiftbic_test.go) and the [corpus regression check](../tests/accuracy_test.go). Eight- and eleven-character shapes near SWIFT context, with invalid country-code look-alikes.

| Set / observed limit | Input example | Why it remains |
|---|---|---|
| development: `swiftbic/positive/0/multiline` | `request accepted ↵ SWIFT: TESTGBIK ↵ worker finished` | Explanation 1 below. |

1. The nearby SWIFT keyword permits alphabetic BIC shapes; ordinary words such as accepted or finished can satisfy the format. Institution assignment is not checked.

## uk sortcode

![Held-out uk_sortcode precision and recall](images/accuracy-uk_sortcode.svg)

Verified by the [uk_sortcode format tests](../internal/detect/sortcode_test.go) and the [corpus regression check](../tests/accuracy_test.go). Separated sort codes, context words, and overlong sequences as negatives.

At the default threshold, no misses or false alarms appeared in either set.

## Regeneration

```sh
make accuracy-doc
python3 scripts/generate_accuracy.py --check
python3 scripts/accuracy_figures.py --check
go -C tests test -run "Test(Accuracy|GeneratedAccuracy)" .
```

The 0.7 results improve PAN, My Number and phone precision on both sets without losing recall in these samples; the default retains their ambiguous business identifiers. Email and encoded-form recall improve on both sets. SWIFT word false positives remain: the rejected attachment rule improved development precision but failed held-out evaluation. The development suite includes regressions for reserved IBAN check digits 00, 01 and 99 and the detector rejects them before MOD 97. The four formerly held-out false positives are fixed; this historical set is now regression evidence, not unseen evaluation.

PEM samples test headers, not full private keys. Generated service tokens test syntax, not authentication. Do not use synthetic identities, account or phone values for transactions or contacting people.

[Support maintenance](https://github.com/sponsors/nao1215).


## Forgotten credentials: independent synthetic corpus

Development seed 120026 and fresh held-out seed 120928 use separate surrounding templates. The initial held-out seed 120927 exposed overlong assignment spans at closing punctuation (227 TP / 133 FP / 133 FN, precision and recall 63.1%). Its templates were then promoted to development; it is not counted as independent final evidence. The replacement set was frozen after that grammar repair and before scoring. The generator does not call embargo, and exact original-byte spans are scored. Each family also sees 120 negatives per category: ordinary prose/IDs, labeled IDs, UUIDs, commit SHAs, URL hashes and public random IDs. No live keys are used. These public samples are no longer unseen data after evaluation.

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


## Default policy decision

Scanner, slog, adapters and embargotest keep threshold 0. NewScanner and the zero Scanner now omit KindHighEntropy; WithAll or WithKinds(KindHighEntropy) enables it. The historical credential held set gave entropy 50.0% precision and 98.3% recall: public random IDs share the token distribution. The real-log study removed 273 path findings but cannot establish that a bare random token is a secret. Opt-in keeps that trade-off visible instead of disguising it with a confidence adjustment. Slog and adapters honor the explicit Scanner supplied by the caller, while embargotest favors finding forgotten values. Threshold 0.5 removes business-label candidates but retains PAN checksum failures and loses every unlabeled entropy finding. Threshold 0.7 additionally loses bank-account and some sort-code findings. Neither becomes a hidden default. Choose a threshold explicitly for the selected kinds; confidence is not probability. SWIFT development precision remains 54.9%; changing the global threshold does not repair ambiguous alphabetic bank codes.


## Choosing a threshold

The default remains 0 for all 26 default kinds. Public-log rates are sample estimates on 239,887,568 bytes; precision treats published contacts/endpoints as sensitive references. Absolute public-log misses are unknown because undetected secrets are not labeled. Synthetic precision and misses use each default kind alone with the existing exact-span labels, including the credential sets; opt-in entropy and country kinds are excluded. The LogHub splits were inspected before; the operations-log held files were labeled and seen but not used to choose rules.

| Minimum confidence | Public FP/GB | Public precision | Development precision / misses | Held precision / misses |
|---|---:|---:|---:|---:|
| 0.0 | 2859.7 | 99.9210% | 95.54% / 0 | 96.09% / 0 |
| 0.5 | 2859.7 | 99.9210% | 97.84% / 0 | 98.40% / 0 |
| 0.7 | 2859.7 | 99.9210% | 99.38% / 158 | 100.00% / 156 |

Choose 0 when retaining ambiguous secrets is the priority. On these synthetic sets, 0.5 removes business-label false positives without additional misses; validate it against your own mislabeled secrets before opting in. A global 0.7 loses bank-account and sort-code positives. These thresholds do not fix the remaining public-log ABA/SWIFT false positives. Select relevant kinds and sensitive keys before raising the global cutoff; confidence is not a probability. Regenerate with make accuracy-doc and make real-log-accuracy; python3 scripts/accuracy_figures.py --check verifies this table.


## Severity and residual exposure

These evaluation tiers are private to the test suite. Critical covers credentials, service and payment tokens, cloud and VCS tokens, private keys, PAN and JWT. High covers national IDs, bank accounts, IBAN and routing numbers, including UK sort codes. Email, phone, IP, crypto addresses and the remaining kinds are standard. Tier labels do not change the public Scanner API.

Each split combines the original synthetic corpus, credentials and the frozen country corpus. Each detector runs alone through WithKinds; opt-in families are included in these evaluation counts. See [country results](countries.md) for their separate precision and recall. Recall still requires an exact kind and span; residual exposure independently counts original bytes outside the union of masked ranges for every expected secret. A partially masked value remains exposed. Overlapping findings cover a byte once, and an invalid range follows Mask’s whole-input redaction rule. The [per-secret ledger](../tests/testdata/residual-exposure.json) records every expected range and its unmasked byte count at threshold zero, including zeros. These historical held fixtures are regression evidence after inspection.

| Set | Tier | Threshold | TP / FP / misses | Recall | Exposed values / bytes |
|---|---|---:|---:|---:|---:|
| development | critical | 0.0 | 1648 / 97 / 0 | 100.00% | 0 / 0 |
| development | high | 0.0 | 3930 / 1089 / 0 | 100.00% | 0 / 0 |
| development | standard | 0.0 | 1724 / 176 / 0 | 100.00% | 0 / 0 |
| development | critical | 0.5 | 1648 / 64 / 0 | 100.00% | 0 / 0 |
| development | high | 0.5 | 3930 / 0 / 0 | 100.00% | 0 / 0 |
| development | standard | 0.5 | 1604 / 24 / 120 | 93.04% | 120 / 4800 |
| development | critical | 0.7 | 1648 / 0 / 0 | 100.00% | 0 / 0 |
| development | high | 0.7 | 3164 / 0 / 766 | 80.51% | 766 / 10735 |
| development | standard | 0.7 | 1604 / 24 / 120 | 93.04% | 120 / 4800 |
| held | critical | 0.0 | 1632 / 96 / 0 | 100.00% | 0 / 0 |
| held | high | 0.0 | 3920 / 1088 / 0 | 100.00% | 0 / 0 |
| held | standard | 0.0 | 1702 / 150 / 2 | 99.88% | 2 / 80 |
| held | critical | 0.5 | 1632 / 64 / 0 | 100.00% | 0 / 0 |
| held | high | 0.5 | 3920 / 0 / 0 | 100.00% | 0 / 0 |
| held | standard | 0.5 | 1584 / 0 / 120 | 92.96% | 120 / 4800 |
| held | critical | 0.7 | 1632 / 0 / 0 | 100.00% | 0 / 0 |
| held | high | 0.7 | 3156 / 0 / 764 | 80.51% | 764 / 10720 |
| held | standard | 0.7 | 1584 / 0 / 120 | 92.96% | 120 / 4800 |

The critical gate requires the current 100% exact-span recall and zero residual bytes in each split at threshold zero. Updating a snapshot cannot relax this assertion. Unit tests inject a partial mask, overlapping ranges, missing findings and an empty corpus to check the gate and exposure calculation.

The default confidence decision is 0 for every tier. Critical precision improves at 0.7 on these committed fixtures, but the fixtures do not establish that a mislabeled card can be discarded safely; a business label can reduce a real PAN’s score to 0.4. High loses 760 development and 758 held findings at 0.7, leaving 10,687 and 10,672 bytes exposed, including SSN, ITIN and modern RRN. Standard loses all 120 entropy positives in each split at 0.5. Entropy remains opt-in because its public-ID negatives have the same value distribution. These observations support retaining findings and selecting kinds or sensitive keys for a particular output boundary; they do not support an implicit per-tier cutoff.


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
| ca_sin | 0.0 | 1,862.8 | 0.0 | 106.7 |
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
| phone_jp | 2,607.9 | 0.0 | 0.0 | 0.0 |
| phone_us | 0.0 | 0.0 | 0.0 | 0.0 |
| private_key_pem | 0.0 | 0.0 | 0.0 | 0.0 |
| service_token | 0.0 | 0.0 | 0.0 | 0.0 |
| slack_token | 0.0 | 0.0 | 0.0 | 0.0 |
| swiftbic | 739,274.8 | 0.0 | 343.8 | 0.0 |
| uk_nhs | 0.0 | 0.0 | 0.0 | 2,287.9 |
| uk_nino | 0.0 | 0.0 | 0.0 | 0.0 |
| uk_sortcode | 0.0 | 0.0 | 0.0 | 0.0 |
| us_itin | 0.0 | 0.0 | 0.0 | 0.0 |
| us_ssn | 0.0 | 20,490.6 | 0.0 | 379.3 |

| Configuration | Development before / GB | Development after / GB | Held before / GB | Held after / GB |
|---|---:|---:|---:|---:|
| WithAll | 827,818.9 | 22,353.3 | 145,650.6 | 2,773.9 |
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
| system (LogHub) | development | 4 | 8,052,486 | 22,353.3 | 0.0 | ca_sin, us_ssn |
| system (LogHub) | held | 4 | 84,357,362 | 2,773.9 | 0.0 | ca_sin, uk_nhs, us_ssn |
| web access | development | 2 | 19,129,354 | 0.0 | 0.0 | none |
| web access | held | 1 | 2,370,789 | 72,549.7 | 1,265.4 | ca_sin, high_entropy, swiftbic, uk_nhs, us_ssn |
| Kubernetes audit | development | 1 | 92,794,383 | 0.0 | 0.0 | none |
| cloud audit | development | 1 | 16,030,714 | 0.0 | 0.0 | none |
| cloud audit | held | 2 | 17,152,480 | 81,154.4 | 39,819.3 | credential, high_entropy, in_aadhaar, mynumber |

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
