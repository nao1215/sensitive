# Measured application masking comparison

This compares overlapping use cases, not overall library quality or adoption. masq v0.2.3 (`1f7750ea536855e965a421bfd47f4057c3ba605d`) offers a convenient slog ReplaceAttr, type/tag/name/prefix rules, allowed types and custom censors/redactors. embargo adds built-in detection, output-safe values, multiple logger adapters and application output assertions. These measurements use unreleased embargo source; the exact source fingerprint is recorded with the results.

## Correctness before speed

The first eight cases reproduce the original comparison probe. Both libraries receive identical events through slog.JSONHandler. masq gets precompiled email and 13–19 digit card regexes, Password/password/token field rules and `masq:"secret"`, with time.Time and slog.Level allowed; embargo selects email/PAN detectors, confidence 0.7 and its default sensitive keys plus `recovery`. The tagged Recovery field is protected by that key rule in embargo. These are practical documented configurations; neither claims that regex syntax provides a checksum validator.

<!-- correctness:start -->
| Case | masq v0.2.3 output fragment | embargo output fragment |
|---|---|---|
| nested_struct | `"user":{"ID":"u123","Email":"[REDACTED]"}` | `"user":{"ID":"u123","Email":"[REDACTED]"}` |
| message | `"msg":"[REDACTED]"` | `"msg":"login failed for [REDACTED]"` |
| attribute_key | `"alice@example.com":"ok"` | `"[REDACTED]":"ok"` |
| group_name | `"alice@example.com":{"status":"ok"}` | `"[REDACTED]":{"status":"ok"}` |
| marshal_json | `"email":"alice@example.com"` | `"email":"[REDACTED]"` |
| wrapped_error | `"error":"[REDACTED]"` | `"error":"request failed: [REDACTED]"` |
| opaque_password | `"Password":"[REDACTED]"` | `"Password":"[REDACTED]"` |
| secret_wrapper | `"Password":"[REDACTED]"` | `"Password":"[REDACTED]"` |
| tag_or_key | `"Recovery":"[REDACTED]"` | `"Recovery":"[REDACTED]"` |
| valid_card | `"card":"[REDACTED]"` | `"card":"[REDACTED]"` |
| invalid_luhn | `"order":"[REDACTED]"` | `"order":"4111111111111112"` |
| map | `"data":{"count":17,"email":null,"password":null}` | `"data":{"count":17,"email":"[REDACTED]","password":"[REDACTED]"}` |
<!-- correctness:end -->

masq requires user rules to find the email and card; plain `masq.New()` does not detect them. Its standard redactor removes an entire matched message/error string; embargo keeps the surrounding context. masq can use RedactString for partial replacement or a custom censor for validation. With this configuration it leaves attribute keys, group names and custom MarshalJSON-generated data visible. Both retain struct shape; masq v0.2.3 replaces matching interface-valued map entries with null in this fixture, while embargo uses a string marker. These are observed version-specific outputs, not claims that all masq configurations behave identically.

The invalid-Luhn row is a deliberate negative example. embargo's default minimum confidence is zero and also masks such candidates; this comparison explicitly selects 0.7 to reduce false positives. A mislabeled real secret can then be missed. The [accuracy corpus](accuracy.md) covers broader detector tradeoffs; these small fixtures are not a production accuracy estimate.

## Time and allocations

![Median JSON logging cost by event](images/comparison.svg)

<!-- comparison:start -->
| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| Comparison/clean/embargo | 1,419.0 | 152 | 14 |
| Comparison/clean/masq | 4,146.0 | 792 | 50 |
| Comparison/flat/embargo | 4,171.0 | 760 | 25 |
| Comparison/flat/masq | 7,086.5 | 672 | 32 |
| Comparison/large50/embargo | 42,204.5 | 11,289 | 177 |
| Comparison/large50/masq | 70,267.5 | 12,710 | 561 |
| Comparison/map/embargo | 9,541.5 | 1,496 | 56 |
| Comparison/map/masq | 12,469.0 | 1,744 | 63 |
| Comparison/nested/embargo | 7,959.0 | 960 | 44 |
| Comparison/nested/masq | 11,530.0 | 1,784 | 61 |
| ComparisonFormatter/clean | 1,291.5 | 0 | 0 |
| ComparisonFormatter/flat | 1,420.5 | 32 | 2 |
| ComparisonFormatter/large50 | 16,446.5 | 7,873 | 10 |
| ComparisonFormatter/map | 1,052.5 | 0 | 0 |
| ComparisonFormatter/nested | 1,052.5 | 0 | 0 |
| ComparisonStruct/embargo | 5,121.5 | 1,000 | 42 |
| ComparisonStruct/go_mask | 1,250.5 | 328 | 7 |
| ComparisonText/embargo | 4,720.5 | 1,640 | 42 |
| ComparisonText/godlp | 69,203.5 | 11,714 | 59 |
| StructuredPath/json_shape | 5,109.0 | 1,000 | 42 |
| StructuredPath/old_string | 1,829.0 | 752 | 14 |

Measured 2026-11-16 with go version go1.26.11 linux/amd64, Linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S; GOMAXPROCS=1, ten 200 ms samples per case. Construction is outside the timed loop; JSON encoding and masking are included. Source and dependency fingerprints, CPU affinity and command are in [comparison.json](comparison.json).

For these five configured events, embargo/masq median time ranges from 0.34 to 0.77; below 1 means less time for embargo. The structured JSON path uses 2.79 times the old string-only time. These ratios are regenerated from the same samples as the table.
<!-- comparison:end -->

The five head-to-head events are a flat email/card pair, a nested struct with opaque password and tagged recovery field, a map, a clean event, and 50 attributes (48 clean plus the flat pair). Both loggers use the same io.Discard sink. masq uses its documented WithAllowedType for time.Time and slog.Level, matching embargo's decision to preserve that metadata; this avoids charging masq for an unnecessary reflection traversal. Masker/scanner construction and regex compilation are excluded for both. The tests use prebuilt slog.Attr slices and LogAttrs to avoid attributing caller argument construction to either library.

The generated ratios describe these configured events. Raw samples and confidence intervals matter more than a single rounded speedup. They do not predict tag-only or type-only masq policies, other payloads or machines.

[Raw ten-sample output](comparison.raw.txt), [benchstat comparison including significance, B/op and allocs/op](comparison.benchstat.txt), [benchmark source and correctness assertions](../tests/comparison_test.go).

`StructuredPath/old_string` measures the former encode-then-scan-string work. It is cheaper, but does not preserve structured output or enforce opaque key rules. `StructuredPath/json_shape` includes decoding and walking the encoded values; it preserves JSON semantics and checks the key policy. This extra cost is real. Profiling the initial Decoder.Token implementation attributed about 41% of sampled CPU time to that traversal; validating with encoding/json.Valid and walking the bytes reduced allocations while retaining duplicate keys, JSON string decoding and number precision. There is no reflection walk of scalar attributes or Go objects in embargo; encoding/json performs its usual encoding work.

Run `make comparison-doc` to rerun ten samples, benchstat and all generated comparison artifacts. `python3 scripts/comparison_docs.py --check` and the tests module's TestComparisonDocuments reject stale source fingerprints, evidence, tables or chart. The make target needs Go 1.26.11, Python 3 and benchstat on PATH. Measurements are local CPU results, not promises for other machines, payloads, policies or custom detectors.

## Other overlapping libraries

[Exact outputs for the same events and text fixtures](comparison-libraries.md) are regenerated and asserted by [comparison_libraries_test.go](../tests/comparison_libraries_test.go). The additional timing rows measure different contracts and must not be interpreted as equivalent protection. PIIFormatter and go-mask are faster on their measured tasks: they apply configured field transformations without embargo's text detection, and PIIFormatter removes the nested Any object. godlp is slower on the text fixture but supports phone families embargo does not.

| Library and version | Configuration and useful differences |
|---|---|
| [samber/slog-formatter v1.3.0](https://github.com/samber/slog-formatter/tree/v1.3.0) | [Explanation 1](#table-explanation-1) |
| [bytedance/godlp v1.2.15](https://github.com/bytedance/godlp/tree/v1.2.15) | [Explanation 2](#table-explanation-2) |
| [showa-93/go-mask v0.6.2](https://github.com/showa-93/go-mask/tree/v0.6.2) | [Explanation 3](#table-explanation-3) |
| [ggwhite/go-masker v3.3.0](https://github.com/ggwhite/go-masker/tree/v3.3.0) | [Explanation 4](#table-explanation-4) |
| [cockroachdb/redact v1.1.8](https://github.com/cockroachdb/redact/tree/v1.1.8) | [Explanation 5](#table-explanation-5) |
| [zap v1.28.0](https://github.com/uber-go/zap/tree/v1.28.0) | [Explanation 6](#table-explanation-6) |
| [OTel Collector redaction processor v0.165.1](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.165.1/processor/redactionprocessor) | [Explanation 7](#table-explanation-7) |

## Remaining use cases

embargo cannot automatically identify arbitrary unregistered secrets; use Secret, a key rule or a custom detector. It does not return a typed masked struct copy, apply per-field partial display policies, preserve safe/unsafe provenance, or centrally enforce OTel pipelines. JSON response/export masking is covered by MaskJSON when the boundary accepts JSON bytes; callers that need a typed copy for further business logic still benefit from struct-copy libraries. Non-JSON formats, encoded binary data, unsupported phone/identity families, custom method side effects and data added downstream need separate handling and output tests. URL/DSN credentials, additional token detectors and package-wide output checks are covered by the Round 12 scenario suite below. An error-wrapping helper is intentionally absent because preserving Unwrap also exposes the original error text.

[Tag migration and database/config inputs](values.md), [shared logging semantics](logging.md), [keep an existing masker and test its real output](testing-output.md), [security scan decisions](security-scans.md).

[Support maintenance](https://github.com/sponsors/nao1215).

## Service leak scenarios

The runnable `scenarioService` handles HTTP requests using a database DSN, an opaque password, a synthetic third-party token, wrapped and joined errors, and either slog or zap. The comparison configures masq's documented field rules and email/PAN regexes, slog-formatter's documented FormatByKey rules for password/token, and go-mask's registered field masks. No library receives an oracle containing the planted values. Users can extend all of these configurations; this measures the listed configurations, not every possible custom rule. go-mask processes attribute containers before logging; message text is outside that field policy. Redirect responses bypass every logger, so an output guard remains necessary.

<!-- leak-scenarios:start -->
| Service output | embargo slog | embargo zap | masq v0.2.3 | slog-formatter v1.3.0 | go-mask v0.6.2 |
|---|---|---|---|---|---|
| declared | caught | caught | caught | caught | caught |
| config | caught | caught | caught | leaked | leaked |
| error | caught | caught | caught | leaked | leaked |
| joined | caught | caught | leaked | leaked | leaked |
| request | caught | caught | leaked | leaked | leaked |
| token | caught | caught | leaked | leaked | leaked |
| redirect | leaked | leaked | leaked | leaked | leaked |
<!-- leak-scenarios:end -->

Run `make leak-scenarios` to regenerate this table. `TestLeakScenarios` checks it for staleness, and `TestLeakScenarioGuard` verifies that a real recorder rejects the planted logs and accepts the masked slog and zap variants. Caught means the entire planted value disappeared from the observed output; it does not imply arbitrary secrets are detected. SDK serialization and unrelated output paths require their own checks.

The staleness check fingerprints embargo production code, comparison tests, the Go/toolchain directives and the compared libraries with their reached module dependencies. An unrelated SDK bump, such as Sentry, no longer invalidates timing evidence. `comparison.json` also keeps `full_source_sha256`, including complete tests/go.mod and tests/go.sum, so the original environment remains auditable. When a compared library changes, recheck its dependency closure with `go list -deps` and remeasure; changing its code paths still invalidates the comparison.

## Table explanations

<a id="table-explanation-1"></a>

PIIFormatter for email/card/user/data; preserves a four-character prefix of long strings, preserves ID fields in slog groups, and replaces Any objects with a marker rather than preserving their nested JSON fields. The same five events are measured.

<a id="table-explanation-2"></a>

Embedded documented rules 1/2/6/16/20/35 for phone/email/card/IP; no rewritten detector regexes. It masks email/card partially, detects but deliberately does not mask IP under its default IP rule, and handles US/Chinese phones rather than embargo's Japanese phone family. The table shows both Japanese and US fixtures. The project has been archived since 2023.

<a id="table-explanation-3"></a>

Documented fixed string masker plus field registration for Email/Password/Recovery/email/password/card; same event payloads and nested struct. It returns a Go value copy suitable for callers that need that type, rather than encoded JSON.

<a id="table-explanation-4"></a>

Tag-based copies and field-specific partial masking for API display; also Sensitive[T] wrappers with Reveal and an optional full-redaction mode. Reviewed for scope; no performance ranking is claimed here.

<a id="table-explanation-5"></a>

Safe/unsafe markers and redactable formatting let an application mark trusted context and later strip unsafe spans. embargo does not provide a provenance-preserving redactable string format.

<a id="table-explanation-6"></a>

ObjectMarshaler/LogObjectMarshaler and typed fields let application code select exactly what to emit. The embargo adapter also examines the final encoded bytes, but is not a substitute for domain-specific allowlisting.

<a id="table-explanation-7"></a>

Collector-side allowed/ignored keys, regex rules and hashing can enforce a centralized telemetry policy outside a Go process. embargo does not provide a Collector processor, telemetry allowlist or keyed pseudonymization.
