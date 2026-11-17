# Measured application masking comparison

This compares overlapping use cases, not overall library quality or adoption. pii-shield v3.0.0 (default policy plus the recovery key, fixed salt) and ferret-scan v1.10.0 (all default checks, Simple strategy) rewrite each encoded slog line before the sink, the position their documentation gives for in-process use; pii-shield also runs as a sidecar and ferret-scan scans files, which are not measured here. masq v0.2.3 offers a convenient slog ReplaceAttr, type/tag/name/prefix rules, allowed types and custom censors/redactors. embargo adds built-in detection, output-safe values, multiple logger adapters and application output assertions. The exact measured production and benchmark source fingerprint is recorded with the results.

## Keeping a known secret out: typed wrappers

embargo `Secret` and ggwhite/go-masker v3.3.0 `Sensitive` are the two typed wrappers among the measured libraries. The test renders one wrapped password through each standard output path; hidden means the value is absent from the output, and error means the encoder refused the type. go-masker's `Sensitive` also offers partial-display maskers and database `Scan`/`Value`, which this table does not score.

<!-- secret-types:start -->
| Output path | embargo Secret | ggwhite/go-masker v3.3.0 Sensitive |
|---|---|---|
| `fmt` `%v` and `%s` | hidden | hidden |
| `fmt` `%+v` of a struct field | hidden | hidden |
| `fmt` `%+v` of an unexported field | hidden | visible |
| `fmt` `%#v` | hidden | hidden |
| `fmt` `%x` and `%q` | hidden | hidden |
| error built with `fmt.Errorf` | hidden | hidden |
| `encoding/json` struct field | hidden | hidden |
| `encoding/xml` struct field | hidden | hidden |
| `encoding/gob` struct field | error | error |
| `text/template` value | hidden | hidden |
| `slog` JSON attribute | hidden | hidden |
| `slog` text attribute | hidden | hidden |
<!-- secret-types:end -->

## Correctness before speed

The first eight cases reproduce the original comparison probe. Both libraries receive identical events through slog.JSONHandler. masq gets precompiled email and 13–19 digit card regexes, Password/password/token field rules and `masq:"secret"`, with time.Time and slog.Level allowed; embargo selects email/PAN detectors, default confidence 0 and its default sensitive keys plus `recovery`. The tagged Recovery field is protected by that key rule in embargo. These are practical documented configurations; neither claims that regex syntax provides a checksum validator.

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
| invalid_luhn | `"order":"[REDACTED]"` | `"order":"[REDACTED]"` |
| map | `"data":{"count":17,"email":null,"password":null}` | `"data":{"count":17,"email":"[REDACTED]","password":"[REDACTED]"}` |
<!-- correctness:end -->

masq requires user rules to find the email and card; plain `masq.New()` does not detect them. Its standard redactor removes an entire matched message/error string; embargo keeps the surrounding context. masq can use RedactString for partial replacement or a custom censor for validation. With this configuration it leaves attribute keys, group names and custom MarshalJSON-generated data visible. Both retain struct shape; masq v0.2.3 replaces matching interface-valued map entries with null in this fixture, while embargo uses a string marker. These are observed version-specific outputs, not claims that all masq configurations behave identically.

The invalid-Luhn row is a deliberate negative example. embargo uses its default minimum confidence of zero and masks this candidate. go-masker with its opt-in Luhn check keeps the invalid-card control, while masq also changes it; the matrix displays these costs beside positive catches. The [accuracy corpus](accuracy.md) covers broader detector tradeoffs; these small fixtures are not a production accuracy estimate.

## Time and allocations

![Median JSON logging cost by event](images/comparison.svg)

<!-- comparison:start -->
| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| Comparison/clean/embargo | 2,104.0 | 32 | 4 |
| Comparison/clean/ferret-scan | 1,143,867.5 | 103,128 | 692 |
| Comparison/clean/go-masker | 2,854.0 | 8 | 1 |
| Comparison/clean/masq | 5,797.0 | 792 | 50 |
| Comparison/clean/pii-shield | 9,272.5 | 488 | 4 |
| Comparison/clean/plain | 871.2 | 0 | 0 |
| Comparison/flat/embargo | 2,774.0 | 96 | 2 |
| Comparison/flat/ferret-scan | 1,281,496.5 | 143,306 | 766 |
| Comparison/flat/go-masker | 2,955.5 | 48 | 3 |
| Comparison/flat/masq | 6,354.5 | 672 | 32 |
| Comparison/flat/pii-shield | 9,897.0 | 702 | 11 |
| Comparison/flat/plain | 820.2 | 0 | 0 |
| Comparison/large50/embargo | 27,196.0 | 6,242 | 5 |
| Comparison/large50/ferret-scan | 6,919,763.5 | 401,052 | 886 |
| Comparison/large50/go-masker | 28,945.0 | 2,096 | 4 |
| Comparison/large50/masq | 119,604.0 | 12,707 | 561 |
| Comparison/large50/pii-shield | 82,969.5 | 8,370 | 12 |
| Comparison/large50/plain | 7,657.0 | 2,048 | 1 |
| Comparison/map/embargo | 6,366.5 | 674 | 18 |
| Comparison/map/ferret-scan | 1,647,775.0 | 150,434 | 746 |
| Comparison/map/go-masker | 7,107.5 | 1,448 | 29 |
| Comparison/map/masq | 11,414.0 | 1,744 | 63 |
| Comparison/map/pii-shield | 14,410.5 | 1,184 | 22 |
| Comparison/map/plain | 2,308.5 | 288 | 9 |
| Comparison/nested/embargo | 4,639.5 | 354 | 7 |
| Comparison/nested/ferret-scan | 1,750,713.5 | 151,912 | 734 |
| Comparison/nested/go-masker | 6,053.0 | 800 | 19 |
| Comparison/nested/masq | 10,354.5 | 1,784 | 61 |
| Comparison/nested/pii-shield | 15,790.5 | 960 | 18 |
| Comparison/nested/plain | 1,162.5 | 0 | 0 |
| ComparisonFormatter/clean | 1,152.5 | 0 | 0 |
| ComparisonFormatter/flat | 1,244.5 | 32 | 2 |
| ComparisonFormatter/large50 | 15,433.0 | 7,872 | 10 |
| ComparisonFormatter/map | 900.0 | 0 | 0 |
| ComparisonFormatter/nested | 904.1 | 0 | 0 |
| ComparisonStruct/embargo | 3,223.5 | 410 | 7 |
| ComparisonStruct/go_mask | 1,115.0 | 328 | 7 |
| ComparisonText/embargo | 3,805.5 | 1,184 | 26 |
| ComparisonText/godlp | 60,772.5 | 11,713 | 59 |
| StructuredPath/json_shape | 3,233.0 | 410 | 7 |
| StructuredPath/old_string | 1,232.5 | 576 | 7 |

Measured 2026-11-17 with go version go1.26.11 linux/amd64, Linux/amd64, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S; GOMAXPROCS=1, ten 200 ms samples per case. Construction is outside the timed loop; JSON encoding and masking are included. Source and dependency fingerprints, CPU affinity and command are in [comparison.json](comparison.json).

For these five configured events the median time ratio embargo/pii-shield ranges from 0.23 to 0.44, embargo/go-masker from 0.74 to 0.94, embargo/masq from 0.23 to 0.56 and embargo/ferret-scan from 0.00 to 0.00; below 1 means less time for embargo. The structured JSON path uses 2.62 times the old string-only time. These ratios are regenerated from the same samples as the table.
<!-- comparison:end -->

The five head-to-head events are a flat email/card pair, a nested struct with opaque password and tagged recovery field, a map, a clean event, and 50 attributes (48 clean plus the flat pair). All four paths use the same io.Discard sink. masq uses its documented WithAllowedType for time.Time and slog.Level, matching embargo's decision to preserve that metadata; this avoids charging masq for an unnecessary reflection traversal. Masker/scanner construction and regex compilation are excluded for every path. The tests use prebuilt slog.Attr slices and LogAttrs to avoid attributing caller argument construction to any library.

The generated ratios describe these configured events. Raw samples and confidence intervals matter more than a single rounded speedup. They do not predict tag-only or type-only masq policies, other payloads or machines.

[Raw ten-sample output](comparison.raw.txt), [benchstat comparison including significance, B/op and allocs/op](comparison.benchstat.txt), [benchmark source and correctness assertions](../tests/comparison_test.go).

`StructuredPath/old_string` measures the former encode-then-scan-string work. It is cheaper, but does not preserve structured output or enforce opaque key rules. `StructuredPath/json_shape` includes decoding and walking the encoded values; it preserves JSON semantics and checks the key policy. This extra cost is real. Profiling the initial Decoder.Token implementation attributed about 41% of sampled CPU time to that traversal; validating with encoding/json.Valid and walking the bytes reduced allocations while retaining duplicate keys, JSON string decoding and number precision. There is no reflection walk of scalar attributes or Go objects in embargo; encoding/json performs its usual encoding work.

Run `make comparison-doc` to rerun ten samples, benchstat and all generated comparison artifacts. `python3 scripts/comparison_docs.py --check` and the tests module's TestComparisonDocuments reject stale source fingerprints, evidence, tables or chart. The make target needs Go 1.26.11, Python 3 and benchstat on PATH. Measurements are local CPU results, not promises for other machines, payloads, policies or custom detectors.

## Other overlapping libraries

[Exact outputs for the same events and text fixtures](comparison-libraries.md) are regenerated and asserted by [comparison_test.go](../tests/comparison_test.go). The additional timing rows measure different contracts and must not be interpreted as equivalent protection. PIIFormatter and go-mask are faster on their measured tasks: they apply configured field transformations without embargo's text detection, and PIIFormatter removes the nested Any object. godlp is slower on the text fixture but supports phone families embargo does not.

| Library and version | Configuration and useful differences |
|---|---|
| [samber/slog-formatter v1.3.0](https://github.com/samber/slog-formatter/tree/v1.3.0) | [Explanation 1](#table-explanation-1) |
| [bytedance/godlp v1.2.15](https://github.com/bytedance/godlp/tree/v1.2.15) | [Explanation 2](#table-explanation-2) |
| [showa-93/go-mask v0.6.2](https://github.com/showa-93/go-mask/tree/v0.6.2) | [Explanation 3](#table-explanation-3) |
| [icntswm/go-masker v0.6.1](https://github.com/icntswm/go-masker/tree/v0.6.1) | [Shared scenarios and setup](#shared-scenarios-and-setup) |

## Remaining use cases

embargo cannot automatically identify arbitrary unregistered secrets; use Secret, a key rule or a custom detector. It does not return a typed masked struct copy, apply per-field partial display policies, preserve safe/unsafe provenance, or centrally enforce OTel pipelines. JSON response/export masking is covered by MaskJSON when the boundary accepts JSON bytes; callers that need a typed copy for further business logic still benefit from struct-copy libraries. Non-JSON formats, encoded binary data, unsupported phone/identity families, custom method side effects and data added downstream need separate handling and output tests. URL/DSN credentials, additional token detectors and package-wide output checks are covered by the credential and output scenario suite below. An error-wrapping helper is intentionally absent because preserving Unwrap also exposes the original error text.

[Tag migration and database/config inputs](values.md), [shared logging semantics](logging.md), [keep an existing masker and test its real output](testing-output.md), [security scan decisions](security-scans.md).

[Support maintenance](https://github.com/sponsors/nao1215).

## Service leak scenarios

The runnable `scenarioService` handles HTTP requests using a database DSN, an opaque password, a synthetic third-party token, wrapped and joined errors, and either slog or zap. The comparison configures masq's documented field rules and email/PAN regexes, slog-formatter's documented FormatByKey rules for password/token, and go-mask's registered field masks. No library receives an oracle containing the planted values. Users can extend all of these configurations; this measures the listed configurations, not every possible custom rule. go-mask processes attribute containers before logging; message text is outside that field policy. Redirect responses bypass every logger, so an output guard remains necessary.

<!-- leak-scenarios:start -->
| Service output | embargo slog | embargo zap | pii-shield v3.0.0 | ferret-scan v1.10.0 | masq v0.2.3 | slog-formatter v1.3.0 | go-mask v0.6.2 | go-masker v0.6.1 | godlp v1.2.15 |
|---|---|---|---|---|---|---|---|---|---|
| Password under the key `password` | caught | caught | caught | caught | caught | caught | caught | caught | leaked |
| Config struct holding a database DSN | caught | caught | caught | leaked | caught | leaked | leaked | caught | leaked |
| DSN inside a wrapped error | caught | caught | caught | leaked | caught | leaked | leaked | caught | leaked |
| DSN and an API key joined with errors.Join | caught | caught | caught | leaked | leaked | leaked | leaked | caught | leaked |
| Bearer header value in a log message | caught | caught | caught | leaked | leaked | leaked | leaked | caught | leaked |
| Third-party API key in a log message | caught | caught | caught | leaked | leaked | leaked | leaked | leaked | leaked |
| Redirect URL query, never logged | leaked | leaked | leaked | leaked | leaked | leaked | leaked | leaked | leaked |
<!-- leak-scenarios:end -->

Run `make leak-scenarios` to regenerate this table. `TestLeakScenarios` checks it for staleness, and `TestLeakScenarioGuard` verifies that a real recorder rejects the planted logs and accepts the masked slog and zap variants. Caught means the entire planted value disappeared from the observed output; it does not imply arbitrary secrets are detected. SDK serialization and unrelated output paths require their own checks.

The staleness check fingerprints embargo production code, comparison tests, the Go/toolchain directives and the compared libraries with their reached module dependencies. An unrelated SDK bump, such as Sentry, no longer invalidates timing evidence. `comparison.json` also keeps `full_source_sha256`, including complete tests/go.mod and tests/go.sum, so the original environment remains auditable. When a compared library changes, recheck its dependency closure with `go list -deps` and remeasure; changing its code paths still invalidates the comparison.

## Table explanations

<a id="table-explanation-1"></a>

PIIFormatter for email/card/user/data/password/token; preserves a four-character prefix of long strings, preserves ID fields in slog groups, and replaces Any objects with a marker rather than preserving their nested JSON fields. The same five events are measured.

<a id="table-explanation-2"></a>

Embedded documented rules 1/2/6/16/20/35 for phone/email/card/IP; no rewritten detector regexes. It masks email/card partially, detects but deliberately does not mask IP under its default IP rule, and handles US phones rather than embargo's Japanese phone family. The table shows both Japanese and US fixtures. The US-phone fixture is a measured capability absent from embargo.

<a id="table-explanation-3"></a>

Documented fixed string masker plus field registration for Email/Password/Recovery/email/password/card; same event payloads and nested struct. It returns a Go value copy suitable for callers that need that type, rather than encoded JSON.

## Shared scenarios and setup

All six libraries run the same 13 positive scenarios and two clean controls. The [full synthetic outputs](comparison-scenarios.json) record their exact released versions. The fixtures include cases outside embargo's capabilities: tag-only opaque secrets and US phone numbers. A catch means the original planted value is absent from a nonempty JSON log event; partial masks count, and absence does not imply complete redaction. The catch rate is for these configurations and scenarios, not production accuracy. The clean controls are excluded from its denominator.

![Scenario catch rate with individual results](images/scenario-catch.svg)

| Library | Setup used by the executable probe | Measured strengths and limits |
|---|---|---|
| embargo | Default kinds, default confidence 0, slog wrapper | 11/13; masks keys and groups; misses tag-only secrets and US phones |
| masq v0.2.3 | Two regexes, three field names, one tag; time/level allowed | 6/13; tag-only protection wins; whole-string redaction loses context |
| go-masker v0.6.1 | Default key policy, Luhn cards, safe types, fixed tag rule | 8/13; faster slog events; tags win and embedded JSON ties; partial display values |
| slog-formatter v1.3.0 | PIIFormatter on six sensitive field names | 3/13; fixed field transforms are cheaper; arbitrary message text remains |
| go-mask v0.6.2 | Fixed masker, six registered fields and a fixed struct tag | 3/13; tags win and typed copies aid reuse; message text remains |
| godlp v1.2.15 | Six built-in rules; apply to string and JSON values | 5/13; US phone wins; email/labeled-card partial masking ties; opaque tokens remain |

The labeled and unlabeled card rows expose a context difference: godlp detects the credit-card-labeled message in this fixture, while the unlabeled charge message remains visible. These setup counts describe this harness, not universal effort. No configuration contains the planted secret values. The timing event selects only email and PAN at default confidence 0 for embargo; the scenario matrix uses the default detector set and default confidence 0. The invalid-card control therefore changes, as it does for a new user. go-masker uses its default policy with opt-in Luhn card detection, so the invalid-card control stays visible; its CardRule keeps the last four digits. Its value inspection recognizes credentials inside JSON strings and free text. Its key policies and struct tags offer partial display rules that embargo lacks. TestComparisonMaskerAdapters runs its slog, zap, zerolog and HTTP paths against synthetic credentials; HTTP masks copies of headers and URLs, rather than installing an access logger.

Runtime dependency counts are measured with `go list -deps`, excluding the library's own module and the standard library, and recorded in comparison.json. embargo, masq, go-mask and go-masker have zero external runtime modules on these paths; masq and go-mask declare test dependencies that do not enter an application's binary. slog-formatter reaches four external runtime modules and godlp one. This distinction replaces counts of all go.mod requirements, which unfairly charged test dependencies to consumers.

The four bars in the [time-per-event chart](images/log-event-time.svg) use exactly the same prebuilt request/email/card event, JSONHandler, sink and ten-sample method. The slog-alone bar measures the encoding cost before masking. Compare absolute microseconds and allocations in the full table: faster field transformations and partial redaction perform different work from a detector scan. Build and setup costs are outside the timed loop for every library.
