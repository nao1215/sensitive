# Threat model

Embargo inspects bytes at an output boundary. The application chooses kinds, sensitive keys, canaries and output wrappers; its users choose field values and sometimes field names. A compromised dependency can return hostile formatter results, construct malformed JSON or write directly to a stream. A child under Guard controls both output pipes and any apparent Go test framing. Findings are a classification decision, not proof that a value is a real identity or a secret.

| Actor and controlled bytes | Undesirable result | Executable boundary |
|---|---|---|
| User: text, keys, JSON strings | Unmasked recognized value or destroyed audit context | Encoding and scoping cases in json_test.go |
| Dependency: formatter and LogValuer results | Panic text echoed, invalid JSON or partial record | slog_handler_test.go and json_test.go |
| Child: stdout, stderr, test-start frames | Secret replay, forged test name in diagnostics, unbounded retention | Guard model, embargotest/guard_test.go and embargotest/fuzz_test.go |
| Application: detector, limits, policy | Silent scanner failure or unexpected cross-policy findings | scanner_test.go, model replay and metamorphic tests |
| User: very large or nested input | Superlinear work, stack exhaustion or memory amplification | Adversarial budget tests and scheduled scaling matrix |

## Resource boundaries

Raw Scan accepts arbitrary byte slices and does not impose an input limit. The scheduled matrix measures every detector, WithAll, Mask, MaskJSON and slog at 1 KB, 16 KB, 256 KB, 1 MB and 16 MB, using repeated digit separators, credential prefixes, percent prefixes and IBAN prefixes. Time and allocated bytes are reported per input byte; fixed allocation budgets fail ordinary tests. FuzzAdversarialBudgets also checks allocation amplification and a five-second per-input ceiling in serial fuzz workers, then requires exactly one valid JSON log record. The elapsed-time assertion applies after a call returns; Go's fuzz-session deadline stops workers that do not return. This is a coarse regression budget, not a performance threshold. Scaling is observed on a finite matrix, not a proof for every input. Run the matrix in an isolated job; do not infer an algorithmic regression from a shared-runner wall-time threshold.

MaskJSON limits input/output and cumulative scan work to the limits documented in json.go; JSON nesting is limited to 64. Inputs over 1 MiB or over the nesting bound return a fixed error and no output. The structured normalizer also bounds slog Any values; a failed record is suppressed. Slog messages and typed string attributes use raw Scan and do not inherit the JSON input limit, so callers must bound their record size. Tests cover deep trees, wide objects, large scalars and invalid strings. ScanLines has the documented bufio line limit and returns an error for an oversized line; direct Scan is the path for a caller that explicitly accepts larger lines. Guard and Recorder share a retained-byte budget across streams and reject overflow; timeout and scanner failure prevent replay. A synchronous custom detector can still loop forever: the caller must trust extensions or isolate them in a process.

The same built-in inventory now includes all eleven country detectors in allocation and scaling tests. HTTP, gRPC, OpenTelemetry and Sentry add TestHookAllocationBudget and BenchmarkHookScaling at the same five sizes. Large MaskJSON-backed SDK records measure fail-closed rejection above the JSON limit; HTTP and gRPC remain access-log boundaries and do not mask service wire data. Log metadata that an SDK does not permit the wrapper to replace is either suppressed or explicitly outside the documented wrapper scope. See the [production scenario matrix](adapters.md#production-leak-scenarios).

## Encodings and audit tradeoffs

| Attempt | Status | Test or limit |
|---|---|---|
| JSON Unicode escapes | Caught after JSON decoding | TestAdversarialEncodingBoundary |
| JSON Unicode escapes in text that is not parsed as JSON | Caught for ASCII characters, one layer, with original-byte positions | TestUnicodeEscapedFindings |
| One percent-encoding layer | Caught with original-byte positions | Metamorphic and Lean vector tests |
| Double percent encoding | Limit: no recursive decoding | TestAdversarialEncodingBoundary/double-percent |
| Base64 | Limit for arbitrary text; registered canaries include encoded forms | TestAdversarialEncodingBoundary/base64 |
| Zero-width text | Limit: characters are not removed | TestAdversarialEncodingBoundary/zero-width |
| Letter homoglyphs | Limit: confusable letters are not normalized | TestAdversarialEncodingBoundary/homoglyph |
| Full-width numeric digits | Caught by numeric normalization | internal/detect/fullwidth_test.go |
| A forged redaction marker or finding label | Does not bypass scanning adjacent secrets | TestAdversarialEncodingBoundary |
| Secret split across writes | Caught after complete stream assembly | Guard model and framing fuzz target |
| Secret split across logical fields or lines | Limit: no reconstruction across semantic fields | Caller must mark the owning value or key |
| Fake Go test framing | Names checked for canaries, findings, length and permitted characters | TestGuardForgedTestNamesNeverReachDiagnostics |
| Output flood or inherited pipes | Bounded retention and process timeout | embargotest/guard_test.go and lifecycle tests |

An attacker can choose a username that looks like an email, PAN or national identifier. Masking that field can remove useful audit context even though the value is not private. Select WithKinds for the data present at the boundary, or disable content detectors with WithKinds() and declare only secret fields through WithoutDefaultSensitiveKeys and WithSensitiveKeys. Keep an application-generated opaque audit identifier when correlation matters. An existing literal redaction marker is indistinguishable from one produced by masking; neither a marker nor a printed finding is an authenticity signal.

Unspecified addresses and loopback addresses identify a local endpoint, so ipaddr excludes 0.0.0.0, ::, 127.0.0.0/8 and ::1. Other private and documentation ranges remain findings; applications decide whether such addresses are sensitive. The held split has been inspected and is now regression data. SWIFT/ABA context exclusions now use that seen regression data; they do not establish zero false positives on unseen logs.

Embargo-generated errors use fixed messages apart from checked Guard test names and Recorder sink names and finding kinds, which pass the same canary and scanner checks with a 64-byte limit and letters, digits, underscore, dot, slash, colon and hyphen; a rejected sink name becomes `a sink with an unprintable name`. Guard lists names active in observed test framing at the leaking bytes; completed and paused tests are removed, and resumed tests return. Each name passes the configured canary check and scanner before a 120-byte limit and a character check for letters, digits, underscore, slash, hyphen, dot, equals, comma and space. A rejected name becomes `[redacted test name]`. An opaque secret that is not the configured canary, has no scanner finding and uses these permitted characters can still appear in a test name. Fixtures must use the configured canary. Framing is forgeable, parallel tests can share a stream, and separate pipe readers observe writes in scheduler order; these names help locate a failure but do not prove which test wrote it. Scanner failure without a located finding reports `[unavailable]`. Tests plant opaque values in formatter panics, malformed Input and forged Guard frames and require recognized canaries or rejected names to stay out of diagnostics. Guard may replay safe streams by policy; unknown secrets that have neither a recognizable detector nor a registered canary remain a detection limit. An application or dependency that writes outside the wrapped boundary is outside that wrapper's protection.

Version/build/release/v-labeled dotted numbers can remain visible even when they are real IP addresses; removing that ambiguous version exclusion violates the frozen IP precision floor, so declare an owning sensitive key when those fields contain addresses (TestKnownLimitVersionAddressFieldsProperty).

A mailbox-looking value in SSH scp syntax such as git@host:path remains excluded because the same bytes identify an ordinary Git remote; use an explicit sensitive field for actual mailboxes in that shape (TestKnownLimitSSHRemoteMailbox).

A generic code key does not imply a credential, so an OAuth authorization code under that key needs WithSensitiveKeys("code"); the same name also carries ordinary status and product codes (TestKnownLimitGenericCodeKey).

Credential scanning decodes at most four Go/JSON quote/backslash layers and one percent layer, and does not reconstruct arbitrary encodings or split fields; %#v byte lists are masked as complete credential-key values without decoding the bytes, while embargotest also recognizes a registered canary inside such a list.

Unquoted fmt values with spaces are bounded by the next field or container end and can over-mask adjacent prose; YAML block scalars require indentation under a credential key, and their contents remain masked through the next peer line.

[Support maintenance](https://github.com/sponsors/nao1215).
