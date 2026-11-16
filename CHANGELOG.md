# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Rebuild OTel float and typed-slice values only from sanitized data after masked-key collisions (R18-02; log body, log attributes and span attributes in v0.5.0). [5b9b76c](https://github.com/nao1215/embargo/commit/5b9b76c91cd7d5684c853e5e1763c263e9fc765b).

- Prevent email/JWT threshold leaks caused by floating-point addition in the core scanner and all hooks using it (R18-04; released tags v0.0.2–v0.5.0, including the earlier module names). Accumulate integer scores before conversion so the documented inclusive thresholds retain matching values. [PR #95](https://github.com/nao1215/embargo/pull/95), [61a44a5](https://github.com/nao1215/embargo/commit/61a44a5461e0eacfba0b0d9854dd66eda5f9e491).

- Fix original-key context leaks in slog scalars, errors, bound attributes, groups and LogValuer values (R18-01; v0.4.0–v0.5.0), HTTP query and redirect-query logs (v0.5.0), and boolean/null JSON leaves in MaskJSON and encoded adapters (v0.4.0–v0.5.0). [PR #94](https://github.com/nao1215/embargo/pull/94), [9e0e6f0](https://github.com/nao1215/embargo/commit/9e0e6f049fda9a82747a8fbec4cecae32d9723de).
- Scan both standard slog handler representations, including Duration nanoseconds and TextHandler millisecond timestamps (R18-03; v0.4.0–v0.5.0). A match in either representation masks the forwarded value. [PR #94](https://github.com/nao1215/embargo/pull/94), [9e0e6f0](https://github.com/nao1215/embargo/commit/9e0e6f049fda9a82747a8fbec4cecae32d9723de).

### Fixed

- Preserve OTel log dropped-attribute counts and other telemetry metadata; reject edits the SDK cannot represent without losing counters (R18-05). Add Scanner.MaskJSONContext and stop canceled OTel, slog, HTTP, gRPC and Sentry scans before subsequent detectors or values (R18-06). Pin unreleased adapters to the fixed root commit. [5b9b76c](https://github.com/nao1215/embargo/commit/5b9b76c91cd7d5684c853e5e1763c263e9fc765b).

- Enforce a combined 64-level limit for WithGroup chains and explicit slog groups, including bound attributes (R18-07). [PR #94](https://github.com/nao1215/embargo/pull/94), [9e0e6f0](https://github.com/nao1215/embargo/commit/9e0e6f049fda9a82747a8fbec4cecae32d9723de).

### Docs

- Correct v0.5 default-selection and raw credential-key guidance (R18-08), and make every README-linked example file runnable in an isolated consumer module (R18-09). Include OTel exporters and Guard fixtures in their own examples; reject missing helpers in doc sync checks. [c8a1cfc](https://github.com/nao1215/embargo/commit/c8a1cfc1dbe74c2a0da7f9da6c2a0737a03fc96e).

- Document cancellation boundaries and OTel counter-preserving rejection, and enforce collision and telemetry invariants through repository policies. [5b9b76c](https://github.com/nao1215/embargo/commit/5b9b76c91cd7d5684c853e5e1763c263e9fc765b).

- Describe original-key scanning and scalar representations; retain differential logger and other-hook context checks in the policy inventory. Refresh measured comparison and real-log evidence after their source checks fail. [PR #94](https://github.com/nao1215/embargo/pull/94), [9e0e6f0](https://github.com/nao1215/embargo/commit/9e0e6f049fda9a82747a8fbec4cecae32d9723de).

## [0.5.0] - 2026-11-16

This release adds service and telemetry hooks, opt-in national ID detectors and explicit matching contracts. Users upgrading from v0.4.0 should review the default detector and IP behavior changes in [doc/migration.md](doc/migration.md).

### Service and telemetry hooks

Implementation: [PR #88](https://github.com/nao1215/embargo/pull/88), [76c1692](https://github.com/nao1215/embargo/commit/76c169240e874e100ff007d8c547043af01878ec).

- Add `NewHTTPHandler` in the dependency-free root module for net/http access logs, plus separate `github.com/nao1215/embargo/adapters/grpc`, `github.com/nao1215/embargo/adapters/otel` and `github.com/nao1215/embargo/adapters/sentry` modules. They provide unary/stream server interceptors, log/span exporter wrappers and an error-event `BeforeSend` helper. Existing zap, zerolog and logrus adapters remain separate modules; [adapter Examples and contracts](doc/adapters.md) show each integration.
- HTTP and gRPC mask access records while preserving service requests, responses and errors. OpenTelemetry masks copied telemetry, rejects log batches requiring changes to immutable resource/scope fields and omits span TraceState. Sentry masks a reconstructed event and its sampling context, omits attachments and drops events on masking failure; separate transaction/log/metric callbacks are outside this hook.

### Opt-in national identifiers

Implementation: [PR #88](https://github.com/nao1215/embargo/pull/88), [76c1692](https://github.com/nao1215/embargo/commit/76c169240e874e100ff007d8c547043af01878ec).

- Add 11 kinds: `KindUSSSN`, `KindUSITIN`, `KindUKNINO`, `KindUKNHS`, `KindIndiaAadhaar`, `KindIndiaPAN`, `KindBrazilCPF`, `KindBrazilCNPJ`, `KindChinaResidentID`, `KindKoreaRRN` and `KindCanadaSIN`. Select only the required kinds with `NewScanner(WithKinds(KindUSSSN, KindCanadaSIN))`, or select all 37 built-ins, including entropy and national IDs, with `NewScanner(WithAll())`. `WithKinds` replaces the built-in selection; `NewScanner()` and a zero Scanner keep the 25 default kinds.
- Publish checksum/format validation, confidence policies, exact-span synthetic results and sampled real-log false positives in [country detection](doc/countries.md). These kinds remain opt-in because threshold-zero false positives do not meet the default-selection criteria. Modern Korean RRN detection requires an attached label when the legacy checksum does not apply.

### Detector contracts and adoption guide

Implementation: [PR #87](https://github.com/nao1215/embargo/pull/87), [bde782f](https://github.com/nao1215/embargo/commit/bde782fdde887b75882ed2ac8c1a8f73df479b37); [PR #89](https://github.com/nao1215/embargo/pull/89), [f1f5d80](https://github.com/nao1215/embargo/commit/f1f5d80b6c76cf696ec3202bf8d01b28ce659afd); [PR #90](https://github.com/nao1215/embargo/pull/90), [fb9825a](https://github.com/nao1215/embargo/commit/fb9825a82487ecb8849037594b058c2a0f3f0d18).

- Document matching rules, validation, confidence scores and default selection for every Kind in godoc. Generate the README's 37-kind table from those comments, and check the documented scores and defaults against public scanner behavior. Keep interpretation limits and false-positive guidance in the linked detector guides.
- Reorganize the README around supported outputs, runnable examples and measured evidence, including the new HTTP, gRPC, OpenTelemetry and Sentry boundaries.

### Guard diagnostics and value checks

Implementation: [PR #81](https://github.com/nao1215/embargo/pull/81), [afe881d](https://github.com/nao1215/embargo/commit/afe881d48d3343249becc12f22a7eb42c61c73a3); [PR #83](https://github.com/nao1215/embargo/pull/83), [0839eee](https://github.com/nao1215/embargo/commit/0839eee7502c1b2bd55b5f39e410aba4f71379a1); [PR #86](https://github.com/nao1215/embargo/pull/86), [780b634](https://github.com/nao1215/embargo/commit/780b634915d21ff1782ecd5cde6e1956fb10f949).

- Restore candidate leaking test names in `embargotest.Guard` diagnostics by tracking active, paused and completed tests near observed output. Validate names and their joined representation against canaries, the scanner, character rules and length limits before displaying them; parallel tests and separate stdout/stderr pipes still limit attribution.
- Include the instantiated `Secret` type in `%#v` and `GoString` output while preserving the redaction marker. Make `CheckValue` inspect unexported fmt fields, exposing domain types whose formatters are bypassed there; [migration notes](doc/migration.md) describe assertion and representation changes.

### Default detection and log false positives

Implementation: [PR #81](https://github.com/nao1215/embargo/pull/81), [afe881d](https://github.com/nao1215/embargo/commit/afe881d48d3343249becc12f22a7eb42c61c73a3); [PR #83](https://github.com/nao1215/embargo/pull/83), [0839eee](https://github.com/nao1215/embargo/commit/0839eee7502c1b2bd55b5f39e410aba4f71379a1).

- Make `KindHighEntropy` opt-in through `WithKinds` or `WithAll`; default scanners, Recorder and Guard no longer report unlabeled entropy candidates. Its confidence remains 0.3 and the default minimum confidence remains zero. Credential assignments and provider prefixes stay enabled by default.
- Exclude unspecified and loopback IPv4/IPv6 addresses from `KindIPAddr` while retaining other private endpoints. Reject additional path/hostname fragments, numeric log tails, operational counters and unquoted Java object references in the affected detectors; see [behavior migration](doc/migration.md) for the recall trade-offs.

### Severity gates and measured evidence

Implementation: [PR #81](https://github.com/nao1215/embargo/pull/81), [afe881d](https://github.com/nao1215/embargo/commit/afe881d48d3343249becc12f22a7eb42c61c73a3); [PR #82](https://github.com/nao1215/embargo/pull/82), [83e325c](https://github.com/nao1215/embargo/commit/83e325c17805df1ab35f53d115776978bec1b829); [PR #86](https://github.com/nao1215/embargo/pull/86), [780b634](https://github.com/nao1215/embargo/commit/780b634915d21ff1782ecd5cde6e1956fb10f949); [PR #88](https://github.com/nao1215/embargo/pull/88), [76c1692](https://github.com/nao1215/embargo/commit/76c169240e874e100ff007d8c547043af01878ec).

- Add exact-span residual-exposure measurements and a critical-tier gate requiring 100% recall and zero unmasked expected bytes in the committed corpora. Keep severity classification in the test suite and the default threshold at zero; a higher global threshold can drop genuine findings. [Accuracy results](doc/accuracy.md) retain known misses and per-tier trade-offs.
- Publish sampled false-positive estimates from eight checksum-pinned public log datasets (92.4 MB, 819,576 lines), with licenses and classification rules, plus interleaved kind-selection benchmarks and refreshed library comparisons. Preserve raw evidence and source/dependency fingerprints; sampled log estimates and fixture timings are not deployment-wide guarantees, and previously inspected held data is identified as regression data.

### Testing and CI

Implementation: [PR #83](https://github.com/nao1215/embargo/pull/83), [0839eee](https://github.com/nao1215/embargo/commit/0839eee7502c1b2bd55b5f39e410aba4f71379a1); [PR #85](https://github.com/nao1215/embargo/pull/85), [da42803](https://github.com/nao1215/embargo/commit/da42803e6fd74fa4da85917ba12ad731c4d13122); [PR #86](https://github.com/nao1215/embargo/pull/86), [780b634](https://github.com/nao1215/embargo/commit/780b634915d21ff1782ecd5cde6e1956fb10f949); [PR #88](https://github.com/nao1215/embargo/pull/88), [76c1692](https://github.com/nao1215/embargo/commit/76c169240e874e100ff007d8c547043af01878ec); [PR #89](https://github.com/nao1215/embargo/pull/89), [f1f5d80](https://github.com/nao1215/embargo/commit/f1f5d80b6c76cf696ec3202bf8d01b28ce659afd).

- Add metamorphic checks, Quint lifecycle replay, compiled Lean reference vectors, offline oracles, adversarial fuzz seeds and allocation/scaling budgets. Verify prose, policies and the Actions lockfile in CI, pin the Quint release evaluator, check all adapter dependencies without local replacements, retry module downloads and improve caches. Keep heavier mutation/scaling jobs scheduled; CodeRabbit review is best effort, with green CI and resolved review threads required for merging.

## [0.4.0] - 2026-11-15

This release redesigns the public API after the rename to embargo. See [doc/migration.md](doc/migration.md) for behavior changes.

### Forgotten credentials and output contracts

Implementation: [PR #77](https://github.com/nao1215/embargo/pull/77), [97a0585](https://github.com/nao1215/embargo/commit/97a0585).

- Add `KindCredential`, `KindServiceToken` and `KindHighEntropy` for credential assignments, URL/DSN passwords, provider prefixes and uncertain random-looking tokens; preserve surrounding connection information, mask complete PEM bodies, and reject IBAN reserved check digits. Scanner and output paths retain the caller's confidence policy; publish separate 0, 0.5 and 0.7 results and the entropy trade-off in [accuracy](doc/accuracy.md).

- Add `embargotest.Guard(m, opts...)` for one-line TestMain supervision of stdout, stderr, default slog, t.Log, panic and inherited subprocess output; fail on detected values, canaries, truncation and timeouts, with stream and candidate test names. Add `CheckValue(tb, constructor)` to exercise standard formatting, serialization, templates, slog and wrapped errors with exact failing paths.

- Add `Recorder.Setenv`, `File`, `Header` and `Reader` for standard environment, config-file and HTTP inputs; use the existing Canary as a plain database row value. Cover every new identifier with godoc, runnable Examples and API goldens, and hold homemade types, Secret and Input to the same formatter contract.

- Add generated service leak comparisons for embargo slog/zap, masq, slog-formatter and go-mask, plus in-memory OTel log export, joined-error, HTTP redirect/error and goleak lifecycle checks. Keep the noisy name-analyzer prototype test-only and omit an error wrapper whose Unwrap would re-expose original messages; document both decisions and the standard-interface domain pattern.

### Structured application masking

- Add `Scanner.MaskJSON(data []byte) ([]byte, error)` and `WithSensitiveKeys(keys ...string) ScannerOption` to share detector and normalized key rules across JSON documents, structured slog values and all logger adapters; retain JSON shape, duplicate keys and numeric precision, with bounded work and fixed failures ([optimized JSON traversal](https://github.com/nao1215/embargo/commit/62b655e)) ([PR #76](https://github.com/nao1215/embargo/pull/76), [implementation](https://github.com/nao1215/embargo/commit/66099c0)). The default keys mask opaque passwords, tokens and HTTP authorization/cookie values; callers can extend or replace the set.

- Add `(*Input[T]).Scan(src any) error` for database string/byte columns, copying driver buffers and clearing failed/NULL input; retain the existing text decoder and require explicit Reveal for database writes ([PR #76](https://github.com/nao1215/embargo/pull/76), [implementation](https://github.com/nao1215/embargo/commit/66099c0)). Runnable Examples and API goldens cover each new identifier; docs explain tag migration and why there is no extra tag or ReplaceAttr API.

- Preserve encoded structured Any values in slog JSON output and readable wrapped error text; freeze attached values, mask sensitive groups, and verify application output with plain slog and masq using existing embargotest assertions ([PR #76](https://github.com/nao1215/embargo/pull/76), [implementation](https://github.com/nao1215/embargo/commit/66099c0)). TextHandler displays structured values as compact JSON; Stringer no longer overrides JSON encoding.

- Add versioned head-to-head correctness tests, ten-sample benchmarks, benchstat output, a generated comparison chart and staleness checks; document differences and remaining use cases for masq, slog-formatter, godlp, go-mask, go-masker, cockroachdb/redact, zap and OTel ([PR #76](https://github.com/nao1215/embargo/pull/76), [comparison implementation](https://github.com/nao1215/embargo/commit/66099c0)).

- Add pinned Gosec and daily Trivy filesystem workflows across all modules, with SARIF upload and badges; review the Trivy supply-chain advisory, justify synthetic test findings individually, and update the zerolog adapter's vulnerable x/sys dependency ([PR #76](https://github.com/nao1215/embargo/pull/76), [security changes](https://github.com/nao1215/embargo/commit/66099c0)).

### Accuracy and scanning

- Decode one layer of percent escapes with original byte offsets, lower confidence for business-labeled numeric candidates, reject embedded My Number fragments, and share hint dispatch across selected detectors while removing unnecessary ASCII position maps ([PR #73](https://github.com/nao1215/embargo/pull/73), [implementation](https://github.com/nao1215/embargo/commit/29ce283)). Public API signatures and the default threshold of 0 are unchanged; see the [behavior migration note](doc/migration.md).

- Separate development and held-out synthetic evaluation, publish both default and 0.7 confidence policies, retain reviewed limits, and extend differential, offset and mutation assertions ([PR #73](https://github.com/nao1215/embargo/pull/73), [assertions](https://github.com/nao1215/embargo/commit/789318d)). The stricter SWIFT context experiment was rejected after held-out recall regressed.

- Bound percent-decoding map capacity without addition, skip unused decoding for empty or custom-only scanners, recognize business labels at query boundaries, and reject invalid accuracy-set selections ([PR #73](https://github.com/nao1215/embargo/pull/73), [allocation bound](https://github.com/nao1215/embargo/commit/5a32a38), [review fixes](https://github.com/nao1215/embargo/commit/7d54404)).

### Follow-up review

- Add optional zap, zerolog and logrus modules with JSON output masking, runnable Examples, real-output tests, all-platform CI and a nested-module release plan ([PR #70](https://github.com/nao1215/embargo/pull/70), [implementation](https://github.com/nao1215/embargo/commit/586448a)).

- Replace the README walls of text with checked outputs and generated accuracy/benchmark figures, expand the synthetic corpus, scope unchecked fmt printing to Examples, audit godoc, align badges and add attributed gopher artwork ([PR #70](https://github.com/nao1215/embargo/pull/70), [integration](https://github.com/nao1215/embargo/commit/6eed0a6)).

- Avoid redundant expiry overlap probes before parsing candidates, preserving overlap behavior while reducing measured scan time ([PR #70](https://github.com/nao1215/embargo/pull/70), [implementation](https://github.com/nao1215/embargo/commit/4c5281e)).

- Skip expensive Go checks for documentation-only changes while keeping README/Example checks and CodeQL ([PR #66](https://github.com/nao1215/embargo/pull/66), [cafc62e](https://github.com/nao1215/embargo/commit/cafc62e)).

### Added

- Replace the logo with embargo branding and add a 1280x640 Open Graph image at doc/images/ogp.png for repository settings ([PR #64](https://github.com/nao1215/embargo/pull/64), [573fa10](https://github.com/nao1215/embargo/commit/573fa10)).

- Publish per-detector precision/recall from a labeled synthetic corpus and real Go benchmark samples for Scanner, Mask, Recorder and slog. Make targets generate README tables and tests reject stale output; introduce use cases and installation requirements at the README entrance ([PR #63](https://github.com/nao1215/embargo/pull/63), [1f2b4c2](https://github.com/nao1215/embargo/commit/1f2b4c2)).

- NewSlogHandler masks messages, keys, groups and values with an explicit scanner, freezes WithAttrs values, preserves metadata and clean scalar types, and converts opaque Any/error values to scanned strings. Normalization or detector panics, including panic(nil) compatibility mode, suppress output with a fixed error ([PR #61](https://github.com/nao1215/embargo/pull/61), [8d439b0](https://github.com/nao1215/embargo/commit/8d439b0)).

- Exercise Secret/Input with real fmt, slog, JSON/XML, templates, zap, zerolog, logrus, OTel, Sentry, HTTP and child panic outputs. Generate the README Tested outputs table from the executed acceptance cases; external SDKs remain in tests/go.mod ([PR #60](https://github.com/nao1215/embargo/pull/60), [fa73d0b](https://github.com/nao1215/embargo/commit/fa73d0b)).

- embargotest captures writers, HTTP status/headers/body/trailers and child test processes, verifies expected content, and checks every output with the scanner and an encoded canary. Allow kinds or exact fixture values independently of the canary; empty output, cut-off output, repeated interim headers exceeding the budget, and child lifecycle failures cannot pass ([PR #59](https://github.com/nao1215/embargo/pull/59), [3649bed](https://github.com/nao1215/embargo/commit/3649bed)).

- Secret and Input are now root runtime types. NewSecret wraps a shallow copy with unexported-pointer storage and [REDACTED] display through fmt, slog, JSON, text and XML; Reveal explicitly returns the value. Input copies decoded strings/bytes into a snapshot and rejects marker round trips, including JSON escaping and base64 ([PR #58](https://github.com/nao1215/embargo/pull/58), [c49392c](https://github.com/nao1215/embargo/commit/c49392c)).


Implementation: [PR #56](https://github.com/nao1215/embargo/pull/56), [89eb73c](https://github.com/nao1215/embargo/commit/89eb73c).

### Breaking changes

- Runtime operations now live in embargo. Use NewScanner(WithKinds(KindEmail, KindPAN)) instead of individual WithEmail/WithPAN options or detector.NewX constructors; detector implementations are internal. NewScanner() and a zero Scanner enable all built-ins, including IP addresses and context-based detectors; WithKinds() explicitly selects none and WithAll() resets all.
- Finding has Kind, Start, End and Confidence. Replace DetectorName, SensitiveKind, Is/IsX and Kind() with Kind comparisons, and RawValue with a slice of the original input. Detail structs, typed accessors, interpretation enums, Level and public normalization are removed; use a domain parser when interpretation is needed.
- Detector requires only Scan([]byte) []Finding. Implement custom matching directly instead of detector.NewRegex, Name and Hints. WithDetector appends independently of built-ins; nil or typed-nil detectors and invalid findings panic with fixed messages.
- ScannerOption is sealed and replaces Option. WithKinds replaces the built-in selection; custom registrations no longer replace one another by name. Invalid WithMinConfidence values panic instead of clamping.
- All overlaps are retained and findings are sorted by start, descending end, kind and descending confidence. Remove WithoutDedup and WithSortByPosition. ScanReader is removed; explicitly bound and read the input before Scan, or use ScanLines for independent lines.
- Use embargo.Mask instead of mask.MaskAll with Redact. The replacement is [REDACTED], overlapping spans are merged, and invalid ranges redact the entire text. MaskFunc replaces custom Strategy, Last4, First1Last4, Partial and Hash; its callback receives the merged span and the highest-confidence kind. Filter findings explicitly for per-kind policies.
- Go 1.26.11 is the minimum in both modules, keeping the previous supported Go series and the net/http fix for GO-2026-6859 required by the upcoming HTTP test recorder. The root module still has no requirements.

### Fixed

- Fail Recorder checks when a custom detector panics with nil under GODEBUG=panicnil=1. Successful checks now require the scanner to finish; validator panics remain failures with fixed diagnostics ([PR #62](https://github.com/nao1215/embargo/pull/62), [72e9a6a](https://github.com/nao1215/embargo/commit/72e9a6a)).

- Check normalization-map capacity before sentinel addition and backing-size arithmetic. CodeQL found the two potentially overflowing allocation expressions; a boundary regression checks the arithmetic without allocating oversized input.

- PAN no longer reports numeric fragments embedded in alphanumeric or underscore-delimited identifiers. Compatibility repetition exposed a Sentry event ID false positive; boundary regressions include full-width digits and preserve URL-encoded separators.

- Do not classify decimal components or RFC3339 fractional seconds as ABA routing numbers, even if their digits satisfy the routing checksum. A regression test reproduces the timestamp false positive discovered through real slog output.

### Testing

- Lock the runtime API, constant values and complete method sets with a go/types golden, reject public struct embedding, and require recognized runnable Examples for every public identifier. Preserve internal detection fixtures, independent checksum oracles and rapid shrinking tests.
- Enable the 77-linter union audited across the owner's Go libraries, with named and explained local suppressions, and enforce dependency direction with depguard and go-arch-lint. Add interval-union property and fuzz tests for caller-controlled masking.


## [0.3.0] - 2026-11-15

### Changed

- The module path is now github.com/nao1215/embargo and the root package is `embargo`; replace `github.com/nao1215/sensitive` with `github.com/nao1215/embargo` in imports and `sensitive.` with `embargo.` in code. The API is otherwise unchanged ([PR #54](https://github.com/nao1215/embargo/pull/54), [008655d](https://github.com/nao1215/embargo/commit/008655d)).

## [0.2.2] - 2026-11-15

### Deprecated

- The module is deprecated: development continues as github.com/nao1215/embargo, and this is the last release under github.com/nao1215/sensitive. The `go.mod` deprecation comment makes `go get` and `go list -m -u` point to the new path ([PR #53](https://github.com/nao1215/embargo/pull/53)).

### Changed

- Raise the separate test module minimum to Go 1.26.0, required by `golang.org/x/crypto` v0.59.0; the root library still requires Go 1.22 and has no external dependencies ([PR #52](https://github.com/nao1215/embargo/pull/52), [33da87a](https://github.com/nao1215/embargo/commit/33da87af35dbb5b4ab64b884a29c5daf12279235)).
- Shorten the README around runnable examples, move detailed contracts and benchmarks to linked documentation, and condense public API comments while retaining detector algorithms; keep Contributors unchanged ([PR #51](https://github.com/nao1215/embargo/pull/51), [21ac25a](https://github.com/nao1215/embargo/commit/21ac25a6073b43ddd2c5f8501eda38924dd76bb2)).
- Consolidate runnable examples and check README snippets, expected output, and godoc example placement in the test suite without changing library behavior or dependencies ([PR #51](https://github.com/nao1215/embargo/pull/51), [21ac25a](https://github.com/nao1215/embargo/commit/21ac25a6073b43ddd2c5f8501eda38924dd76bb2)).

## [0.2.1] - 2026-11-14

### Fixed

- Space-delimited UK sort codes followed by whitespace or prose are detected without accepting a following numeric group; classic GitHub tokens require exactly 36 body characters as documented ([PR #47](https://github.com/nao1215/embargo/pull/47), [40d3c95](https://github.com/nao1215/embargo/commit/40d3c95)).

### Changed

- Property-based testing now uses rapid in an isolated test-only module, with specification generators, shrinking, path and masking properties, a labeled recall corpus, targeted mutation checks, and merged cross-module coverage; the root library remains dependency-free ([PR #47](https://github.com/nao1215/embargo/pull/47), [40d3c95](https://github.com/nao1215/embargo/commit/40d3c95)).

## [0.2.0] - 2026-11-14

### Added

- IBAN detection now covers all 89 country formats in SWIFT registry release 103, including 17 previously missing countries ([PR #45](https://github.com/nao1215/embargo/pull/45), [5552698](https://github.com/nao1215/embargo/commit/5552698)).

### Fixed

- IBANs followed by spaces and another word retain their complete original value instead of being rejected; extraction stops at the country-specific length before checking MOD 97 ([PR #45](https://github.com/nao1215/embargo/pull/45), [a66ecbc](https://github.com/nao1215/embargo/commit/a66ecbc)).
- Percent-encoded log/query separators now delimit values consistently, including numeric values whose scanners previously consumed escape digits; malformed escapes are checked against original bytes before full-width normalization, and contextual extractors no longer include escape digits in CVV, expiry, account, trace, or merchant values ([PR #45](https://github.com/nao1215/embargo/pull/45), [3dd2718](https://github.com/nao1215/embargo/commit/3dd2718)).

- The merchant ID detector no longer reports a terminal ID inside a merchant ID it already reported. "Merchant ID A00000000A00000 TID 000" gave both `A00000000A00000` and `00000000`, because only the start offset was checked for duplicates, not the whole range. Found by the scheduled `FuzzScanner` run ([PR #17](https://github.com/nao1215/embargo/pull/17), [5f1042d](https://github.com/nao1215/embargo/commit/5f1042d)).

## [0.1.2] - 2026-09-28

### Fixed

- The card expiry detector no longer reports a second, overlapping date inside one it already reported. "exp 01/01/00" gave both `01/01` and `01/00`, because "exp" is matched once per case variant and each match searched the same range again; "有効期限 01/01/00", matched once, gave only `01/01`. Found by the new `FuzzScanner`.
- The email detector no longer accepts a domain that starts with `.`: "user@.com" and "user@.example.com" were reported with full confidence although the first domain label is empty. Found by the new `FuzzScanner`.

## [0.1.1] - 2026-09-12

### Changed

- The supported Go floor is 1.22 instead of 1.24. Nothing in the tree needs a newer Go: 1.22 is where the detectors' range-over-int stops compiling, so that is the real minimum, and two more Go releases can now use this library. The unit-test matrix runs that floor and the newest release, and the GitHub Actions pins move to `actions/checkout@v7` / `actions/setup-go@v7`.
- CI cross-builds the module for FreeBSD, OpenBSD and NetBSD. A library is reached by `go get` from whatever machine its caller has, and nothing was checking that those three still compile.

### Removed

- The Go Report Card badge. The service is retired and its badge now answers `go report: retired`, which is a line of README saying nothing about this library.

## [0.1.0] - 2026-07-01

### Added

- Developer credential detectors: four new detectors for secrets commonly leaked in source, CI logs, and command lines.
  - `WithGitHubToken()` (`NameGitHubToken`): classic GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36 base62 chars) and fine-grained PATs (`github_pat_` + 22+ chars). Detail: `GitHubTokenDetail{TokenType}`.
  - `WithSlackToken()` (`NameSlackToken`): Slack API tokens (`xoxb-`/`xoxp-`/`xoxa-`/`xoxo-`/`xoxr-`/`xoxs-`). Detail: `SlackTokenDetail{TokenType}`.
  - `WithGoogleAPIKey()` (`NameGoogleAPIKey`): Google API keys (`AIza` + 35 chars). Detail: `GoogleAPIKeyDetail`.
  - `WithPrivateKeyPEM()` (`NamePrivateKeyPEM`): PEM private key headers (`-----BEGIN [ALGO ]PRIVATE KEY-----` for RSA/EC/DSA/OpenSSH/PKCS#8). Detail: `PrivateKeyPEMDetail{KeyType}`.

  All four are classified as `KindCredential`, use hint-based pre-filtering with dedicated byte scanners (no regular expressions), and are included in `WithAll()`. Findings expose `Is*` predicates and `*Detail()` accessors consistent with the existing detectors.

## [0.0.3] - 2026-02-10

### Fixed

- ScanLines buffer limit increased to 1 MB ([6ee98e3](https://github.com/nao1215/embargo/commit/6ee98e3)): The internal `bufio.Scanner` buffer now starts at 64 KB and grows up to 1 MB (previously limited to the default 64 KB). Lines exceeding 1 MB return `bufio.ErrTooLong`. The doc comment now documents this limitation explicitly.
- ScanLines callback receives a safe copy of line bytes ([216ce24](https://github.com/nao1215/embargo/commit/216ce24)): The `line` slice passed to the ScanLines callback is now an independent copy, safe to retain after the callback returns. Previously, the slice pointed into the `bufio.Scanner` internal buffer, which was overwritten on the next `Scan()` call.
- Confidence values clamped to [0, 1] ([2802566](https://github.com/nao1215/embargo/commit/2802566)): `WithMinConfidence` and `detector.NewRegex` now clamp the confidence parameter to the valid range. Values below 0 are treated as 0 and values above 1 are treated as 1.

### Changed

- Clarified minConfidence ordering in documentation ([cc8d13d](https://github.com/nao1215/embargo/commit/cc8d13d)): The `Scanner.Scan` and `WithMinConfidence` doc comments now explicitly state that the confidence threshold is applied after deduplication and sorting, so dedup always sees the full candidate set.
- Extracted duplicated ASCII helpers to `internal/ascii` ([50a6846](https://github.com/nao1215/embargo/commit/50a6846)): `hasASCIILetter`, `asciiLowerCopy`, and `toLowerASCII` were duplicated between `scanner.go` and `detector/context.go`. They are now shared via the `internal/ascii` package, eliminating the risk of future divergence.
- Pre-computed keyword cache for context-based detectors ([7d56c0f](https://github.com/nao1215/embargo/commit/7d56c0f)): Introduced `keywordSet` type that pre-computes lowered keyword forms once at initialization. Context-based detectors (CVV, ACH, card expiry, merchant ID, bank account) no longer call `ascii.LowerCopy` per keyword on every `Scan` invocation.

### Tests

- ScanLines ErrTooLong regression test ([b71bf3d](https://github.com/nao1215/embargo/commit/b71bf3d)): Verifies that lines exceeding the 1 MB buffer return `bufio.ErrTooLong`.
- ScanLines buffer copy safety test ([5e24472](https://github.com/nao1215/embargo/commit/5e24472)): Verifies that retained `line` slices from the callback are not corrupted by subsequent scans.
- WithMinConfidence boundary value tests ([cf0a3f0](https://github.com/nao1215/embargo/commit/cf0a3f0)): Verifies that a finding with confidence exactly equal to the threshold is included, and one below is excluded.
- RawValue == input[Start:End] invariant test ([54eaa2c](https://github.com/nao1215/embargo/commit/54eaa2c)): Verifies across all built-in detectors that every finding's `RawValue` matches the corresponding `input[Start:End]` slice, preventing mask output corruption.

## [0.0.2] - 2026-02-08

### Added

- Stream scanning API ([06cc2b1](https://github.com/nao1215/embargo/commit/06cc2b1)): `ScanReader(io.Reader)` for in-memory scanning and `ScanLines(io.Reader, callback)` for memory-efficient line-by-line streaming. Ideal for log files and large text streams.
- Bitcoin (BTC) address detector ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Detects P2PKH (prefix '1'), P2SH (prefix '3'), Bech32 SegWit v0 (prefix 'bc1q'), and Bech32m Taproot v1–v16 (prefix 'bc1p') addresses. Validates Base58Check (double SHA-256 checksum) for legacy addresses and Bech32/Bech32m polynomial checksums (BIP-173/BIP-350) for SegWit/Taproot addresses. Confidence: 0.95.
- Ethereum (ETH) address detector ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Detects Ethereum addresses (0x + 40 hex characters). Validates EIP-55 mixed-case checksums using Keccak-256. Confidence: 0.80 for all-lowercase/all-uppercase, 0.95 for EIP-55 validated addresses.
- Keccak-256 hash implementation ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Minimal Keccak-f[1600] sponge construction for EIP-55 checksum validation. Zero external dependencies — uses only the Go standard library.
- `WithBTC()` and `WithETH()` scanner options ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Enable individual cryptocurrency address detection.
- `BTCDetail()` and `ETHDetail()` finding accessors ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Type-safe access to detector-specific details (address type, EIP-55 validation status).
- `IsBTC()` and `IsETH()` finding helpers ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Quick detector type checks.
- Kind mapping ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Both BTC and ETH are classified as `KindFinancial`.
- Japanese phone number format expansion ([46d2db8](https://github.com/nao1215/embargo/commit/46d2db8)): Added IP phone (050), M2M/IoT (020), and FMC service (060) prefix detection. Enhanced `JPPhoneDetail` with `JPPhoneType` classification.
- Bank account full-width digit support ([46d2db8](https://github.com/nao1215/embargo/commit/46d2db8)): Bank account detector now normalizes full-width digits for Japanese input.

### Changed

- Reduced cyclomatic complexity ([4b0e022](https://github.com/nao1215/embargo/commit/4b0e022)): Refactored detector implementations (PAN, email, JWT, IBAN, IP address, sort code, SWIFT/BIC, etc.) and scanner internals to reduce cyclomatic complexity and improve maintainability.

## [0.0.1] - 2026-02-08

Initial release of the `sensitive` library.

### Added

- Core scanning engine ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Multi-stage filtering pipeline with hint-based pre-filter (SIMD-optimized `bytes.Contains`), detector execution, and result dedup/sort.
- Scanner options: `WithAll()`, individual `With*()` options, `WithSortByPosition()`, `WithoutDedup()`, `WithCustomDetector()` for user-defined detectors.
- Confidence scoring: Every finding includes a confidence level (0.0--1.0) based on structural validation, checksums, and context keywords.

#### Detectors

- PAN (Payment Card Number) ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects Visa, Mastercard, Amex, Discover, JCB, Diners Club, and UnionPay card numbers with Luhn checksum validation. Supports hyphenated, spaced, and contiguous formats. Full-width digit normalization for Japanese input.
- Email ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Heuristic email address detection using `@` as a pivot point. Validates local and domain parts, TLD, and RFC 5321 label boundary rules. Confidence boosted by known TLD matching.
- Japanese Phone Number ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects mobile (090/080/070), landline (03/06/etc.), and toll-free (0120/0800) Japanese phone numbers. Full-width digit normalization. Prefix-based classification.
- My Number (Japanese national ID) ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects 12-digit My Number with official check digit validation (modular arithmetic per specification). Context keyword support (Japanese/English).
- JWT (JSON Web Token) ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects JWTs via the `eyJ` prefix (base64url of `{"`). Validates three-part structure, decodes header JSON, and extracts the `alg` field. Supports unsigned JWTs (alg:none, CVE-2015-9235). Leading boundary check prevents false matches inside longer base64url strings.
- AWS Access Key ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects AWS access key IDs (`AKIA` prefix + 16 uppercase alphanumeric characters). Context keyword support for key/secret pairs.
- IBAN (International Bank Account Number) ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects IBANs with ISO 13616 mod-97 checksum validation. Supports all standardized country code prefixes and lengths.
- IP Address ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects IPv4 and IPv6 addresses. Uses `net.ParseIP` for validation. Boundary checks reject IPs embedded in identifiers (leading/trailing alphanumeric, `_`, `-`).
- SWIFT/BIC ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects SWIFT/BIC codes (8 or 11 characters). Validates bank code, country code (ISO 3166-1 alpha-2), location code, and optional branch code structure.
- US ABA Routing Number ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects 9-digit ABA routing transit numbers. Validates Federal Reserve routing symbol prefix (01-12, 21-32, 61-72, 80) and ABA checksum (3-7-1 weighted mod-10).
- UK Sort Code ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects UK bank sort codes in `XX-XX-XX` or `XX XX XX` format. Date-like pattern disambiguation with context keyword fallback. Rejects all-zero sort codes (00-00-00).
- CVV/CVC/CID ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based detection of 3-4 digit card verification values near keywords (CVV, CVC, CID, security code, etc.). Japanese keyword support.
- Card Expiry ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based detection of card expiration dates (MM/YY, MM/YYYY, MM-YY). Validates month range (01-12) and year range. Japanese keyword support.
- Payment Token ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects Stripe (`sk_live_`, `pk_live_`, `sk_test_`, `pk_test_`), Square (`sq0atp-`, `sq0csp-`), and PayPal (`access_token$`) API keys/tokens.
- Bank Account ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based weak detection of bank account numbers (4-17 digits) near banking keywords. Japanese and English keyword support. Holder name context boosts confidence.
- ACH Trace Number ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based detection of 15-digit ACH trace numbers. Validates ODFI routing prefix against Federal Reserve routing symbol ranges.
- Merchant/Terminal ID ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based detection of merchant IDs (MID) and terminal IDs (TID) near keywords. Validates alphanumeric sequences of 8-15 characters.
- Custom Detector ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Users can register custom detectors implementing the `Detector` interface via `WithCustomDetector()`. A `RegexDetector` helper is provided for regex-based detection.

#### Masking

- mask package ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Optional masking helper with `Mask()` for single findings and `MaskAll()` for multiple findings. Built-in strategies: `StrategyFull` (full masking) and `StrategyPartial` (preserve first/last N characters).

#### Architecture

- Zero external dependencies: Uses only the Go standard library.
- Multi-stage filtering: Hint-based pre-filtering with case-insensitive ASCII matching skips detectors early, minimizing scan cost.
- Pre-computed hint cache: Hint lowercase normalization is computed once at `NewScanner` construction, not per-scan.
- O(n log n) overlap detection: Dedup uses confidence-descending greedy selection with binary search for overlap checking.
- Full-width digit normalization: Transparent handling of Japanese full-width digits (U+FF10--U+FF19) for PAN, phone, and My Number detection.
- Deterministic output: Findings are sorted by confidence (descending), then by byte offset and detector name for fully reproducible results.

[0.5.0]: https://github.com/nao1215/embargo/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/nao1215/embargo/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/nao1215/embargo/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/nao1215/embargo/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/nao1215/embargo/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nao1215/embargo/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/nao1215/embargo/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/nao1215/embargo/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nao1215/embargo/compare/v0.0.3...v0.1.0
[0.0.3]: https://github.com/nao1215/embargo/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/nao1215/embargo/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/nao1215/embargo/releases/tag/v0.0.1
