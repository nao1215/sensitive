# Measured application masking comparison

This compares overlapping use cases, not overall library quality or adoption. masq v0.2.3 (`1f7750ea536855e965a421bfd47f4057c3ba605d`) offers a convenient slog ReplaceAttr, type/tag/name/prefix rules, allowed types and custom censors/redactors. embargo adds built-in detection, output-safe values, multiple logger adapters and application output assertions. These measurements use unreleased embargo source; the exact source fingerprint is recorded with the results.

## Correctness before speed

The first eight cases reproduce the original comparison probe. Both libraries receive identical events through slog.JSONHandler. masq gets precompiled email and 13–19 digit card regexes, Password/password/token field rules and `masq:"secret"`; embargo selects email/PAN detectors, confidence 0.7 and its default sensitive keys plus `recovery`. The tagged Recovery field is protected by that key rule in embargo. These are practical documented configurations; neither claims that regex syntax provides a checksum validator.

<!-- correctness:start -->
<!-- correctness:end -->

masq requires user rules to find the email and card; plain `masq.New()` does not detect them. Its standard redactor removes an entire matched message/error string; embargo keeps the surrounding context. masq can use RedactString for partial replacement or a custom censor for validation. With this configuration it leaves attribute keys, group names and custom MarshalJSON-generated data visible. Both retain struct shape; masq v0.2.3 replaces matching interface-valued map entries with null in this fixture, while embargo uses a string marker. These are observed version-specific outputs, not claims that all masq configurations behave identically.

The invalid-Luhn row is a deliberate negative example. embargo's default minimum confidence is zero and also masks such candidates; this comparison explicitly selects 0.7 to reduce false positives. A mislabeled real secret can then be missed. The [accuracy corpus](accuracy.md) covers broader detector tradeoffs; these small fixtures are not a production accuracy estimate.

## Time and allocations

![Median JSON logging cost by event](images/comparison.svg)

<!-- comparison:start -->
<!-- comparison:end -->

The five head-to-head events are a flat email/card pair, a nested struct with opaque password and tagged recovery field, a map, a clean event, and 50 attributes (48 clean plus the flat pair). Both loggers use their ordinary timestamp and level handling and the same io.Discard sink. masq's ReplaceAttr also traverses metadata; embargo preserves it. Masker/scanner construction and regex compilation are excluded for both. The tests use prebuilt slog.Attr slices and LogAttrs to avoid attributing caller argument construction to either library.

[Raw ten-sample output](comparison.raw.txt), [benchstat comparison including significance, B/op and allocs/op](comparison.benchstat.txt), [benchmark source and correctness assertions](../tests/comparison_test.go).

`StructuredPath/old_string` measures the former encode-then-scan-string work. It is cheaper, but does not preserve structured output or enforce opaque key rules. `StructuredPath/json_shape` includes decoding and walking the encoded values; it preserves JSON semantics and checks the key policy. This extra cost is real. There is no reflection walk of scalar attributes or Go objects in embargo; encoding/json performs its usual encoding work.

Run `make comparison-doc` to rerun ten samples, benchstat and all generated comparison artifacts. `python3 scripts/comparison_docs.py --check` and the tests module's TestComparisonDocuments reject stale source fingerprints, evidence, tables or chart. The make target needs Go 1.26.11, Python 3 and benchstat on PATH. Measurements are local CPU results, not promises for other machines, payloads, policies or custom detectors.

## Other overlapping libraries

[Exact outputs for the same events and text fixtures](comparison-libraries.md) are regenerated and asserted by [comparison_libraries_test.go](../tests/comparison_libraries_test.go). The additional timing rows measure different contracts and must not be interpreted as equivalent protection.

| Library and version | Configuration and useful differences |
|---|---|
| [samber/slog-formatter v1.3.0](https://github.com/samber/slog-formatter/tree/v1.3.0) | PIIFormatter for email/card/user/data; preserves a four-character prefix of long strings, preserves ID fields in slog groups, and replaces Any objects with a marker rather than preserving their nested JSON fields. The same five events are measured. |
| [bytedance/godlp v1.2.15](https://github.com/bytedance/godlp/tree/v1.2.15) | Embedded documented rules 1/2/6/16/20/35 for phone/email/card/IP; no rewritten detector regexes. It masks email/card partially, detects but deliberately does not mask IP under its default IP rule, and handles US/Chinese phones rather than embargo's Japanese phone family. The table shows both Japanese and US fixtures. The project has been archived since 2023. |
| [showa-93/go-mask v0.6.2](https://github.com/showa-93/go-mask/tree/v0.6.2) | Documented fixed string masker plus field registration for Email/Password/Recovery/email/password/card; same event payloads and nested struct. It returns a Go value copy suitable for callers that need that type, rather than encoded JSON. |
| [ggwhite/go-masker v3.3.0](https://github.com/ggwhite/go-masker/tree/v3.3.0) | Tag-based copies and field-specific partial masking for API display; also Sensitive[T] wrappers with Reveal and an optional full-redaction mode. Reviewed for scope; no performance ranking is claimed here. |
| [cockroachdb/redact v1.1.8](https://github.com/cockroachdb/redact/tree/v1.1.8) | Safe/unsafe markers and redactable formatting let an application mark trusted context and later strip unsafe spans. embargo does not provide a provenance-preserving redactable string format. |
| [zap v1.28.0](https://github.com/uber-go/zap/tree/v1.28.0) | ObjectMarshaler/LogObjectMarshaler and typed fields let application code select exactly what to emit. The embargo adapter also examines the final encoded bytes, but is not a substitute for domain-specific allowlisting. |
| [OTel Collector redaction processor v0.165.1](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.165.1/processor/redactionprocessor) | Collector-side allowed/ignored keys, regex rules and hashing can enforce a centralized telemetry policy outside a Go process. embargo does not provide a Collector processor, telemetry allowlist or keyed pseudonymization. |

## Remaining use cases

embargo cannot automatically identify arbitrary unregistered secrets; use Secret, a key rule or a custom detector. It does not return a typed masked struct copy, apply per-field partial display policies, preserve safe/unsafe provenance, or centrally enforce OTel pipelines. JSON response/export masking is covered by MaskJSON when the boundary accepts JSON bytes; callers that need a typed copy for further business logic still benefit from struct-copy libraries. Non-JSON formats, encoded binary data, unsupported phone/identity families, custom method side effects and data added downstream need separate handling and output tests. URL/DSN credentials, error helpers, additional detectors and new embargotest features are outside this round.

[Tag migration and database/config inputs](values.md), [shared logging semantics](logging.md), [keep an existing masker and test its real output](testing-output.md), [security scan decisions](security-scans.md).

[Support maintenance](https://github.com/sponsors/nao1215).
