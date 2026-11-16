# Scanner behavior changes

## v0.4.0

The public API signatures are unchanged. The API golden continues to check the exported contract. The default minimum confidence remains 0.

Built-in detectors now decode one layer of valid percent escapes before scanning and return byte offsets into the original input. For example, `a%40example.com` is detected and masking replaces the entire original escaped address. Literal `+`, malformed escapes and other encoding families remain unchanged. Custom detectors still receive the original bytes. Applications that already percent-decode a field should account for the scanner decoding one further layer of the bytes it receives.

PAN, My Number and Japanese phone candidates under attached business labels now score 0.4. Default scanners still return them. Lower scores can also change which kind wins an overlap in `MaskFunc`. Applications using a higher `WithMinConfidence` threshold may stop reporting these candidates, including genuine secrets with misleading labels. A global threshold of 0.7 also excludes bank-account findings and some sort codes; select policies per use case using the [accuracy tables](accuracy.md).

My Number findings embedded in ASCII identifiers are rejected. Scanner ordering, overlap handling, custom detector validation, slog scalar scanning and logger metadata handling retain their contracts.

[Support maintenance](https://github.com/sponsors/nao1215).


## v0.4.0: forgotten credentials

NewScanner and WithAll now include credential assignments, URL/DSN secrets, provider token prefixes and confidence-0.3 entropy candidates. Use explicit WithKinds to keep a narrower policy. Threshold 0 is unchanged on every path; passing WithMinConfidence(0.5) discards entropy candidates and business-label numeric candidates, including true secrets with those characteristics. New credential grammar uses original URL bytes to preserve escaped password delimiters, while older built-ins retain percent decoding. WithSensitiveKeys also controls ordinary text assignments; provider-specific field names and URL credentials remain detector rules.

Complete PEM private keys now produce a span through the matching END marker; incomplete inputs still identify the header. Code consuming exact header spans should account for this intentional extension. IBAN check digits 00, 01 and 99 are now rejected even when the remainder is 1.

Guard supervises a child test process and preserves parent globals, so move TestMain setup with externally visible side effects into the guarded lifecycle as needed; TestMain runs in both supervisor and child. Read [testing output](testing-output.md) for bounds, attribution and subprocess limits. CheckValue can validate a domain-owned type without adding embargo imports to that domain package.

## v0.5.0: default detection, log evidence and value checks

NewScanner and the zero Scanner now omit KindHighEntropy. To enable entropy alongside every built-in, construct `embargo.NewScanner(embargo.WithAll())`; this also enables the 11 national ID kinds added in v0.5.0. To preserve a narrower policy, enumerate the required kinds with `WithKinds`; to select only the entropy heuristic, use `WithKinds(KindHighEntropy)`. Minimum confidence remains zero, and the heuristic still reports 0.3. Unlabeled random secrets therefore require explicit entropy selection; key-based credentials and provider prefixes remain in the default set. This selection also applies to the default Recorder and Guard scanners.

`KindIPAddr` no longer reports unspecified or loopback addresses: `0.0.0.0`, `::`, IPv4's `127.0.0.0/8` range and `::1`. Private, link-local and public endpoints remain eligible. Applications that used these local addresses as findings must update their assertions or supply a custom detector when they need that policy; selecting `WithAll` does not restore the old IP behavior.

The 11 new national ID kinds are opt-in and do not change the 25-kind default selection. Use `WithKinds(KindUSSSN, KindCanadaSIN)` for an explicit selection, or `WithAll()` for all 37 kinds. `WithKinds` replaces rather than extends the built-in selection. See [country detection](countries.md) for the full list, false positives and confidence trade-offs before broadening an existing scanner.

Entropy candidates stop at `/` and are rejected next to path separators or dotted name components. SWIFT ignores path and hostname components; PAN, MyNumber and Japanese phone detection reject decimal tails and numeric hostname fragments. PAN also rejects the signed suffix of an underscore-delimited identifier. ABA skips explicit eventTime/downTime/lock/ino assignments, and the token assignment rule omits unquoted Java object references. These rules can miss secrets deliberately placed in those positions; quoted token strings and password/secret assignments retain masking. The [real-log evaluation](accuracy.md#public-system-logs) records both improvements and held-out errors left unchanged.

`fmt.Sprintf("%#v", secret)` and `secret.GoString()` now include the instantiated type, such as `embargo.Secret[string]([REDACTED])`. Update exact string assertions; ordinary formatting, JSON and text encoding still write the marker. Input keeps its existing marker-only format.

CheckValue now inspects unexported struct fields through fmt. A defined string with output methods can fail this check because fmt bypasses those methods in that position. Use Secret or an application-owned struct containing an unexported pointer, as shown in [values.md](values.md). The API boundaries below describe the callers and responsibilities of the public helpers.

## API boundaries

These consumer-facing identifiers have distinct callers. None needs a second option type or a new wrapper. The changes below affect behavior; signatures stay compatible, apart from parameter names recorded by the API golden.

| Identifier | Decision | Use case and boundary |
|---|---|---|
| `WithSensitiveKeys` | Keep | [sensitive keys](#sensitive-keys) |
| `(*Scanner).MaskJSON` | Keep | Sanitize an audit export or HTTP JSON body before sending it; a logger handler cannot cover those outputs. |
| `(*Input[T]).Scan` | Keep | Receive a database text column through `rows.Scan(&input)` and publish its Secret snapshot after loading. |
| `KindCredential` | Keep | Find a password in a DSN, assignment or authorization header even when the value has no recognizable format. |
| `KindServiceToken` | Keep | Recognize provider-prefixed credentials in free text without requiring a sensitive field name. |
| `KindHighEntropy` | Change selection | [entropy selection](#entropy-selection) |
| `embargotest.Guard` | Keep | [guard lifecycle](#guard-lifecycle) |
| `embargotest.CheckValue` | Extend checks | Verify an application-owned secret type across encoders and formatters; now also test fmt inside an unexported field. |
| `(*Recorder).Setenv` | Keep | Inject the configured canary into an environment-based credential loader and delegate restoration to testing.TB. |
| `(*Recorder).File` | Keep | [credential files](#credential-files) |
| `(*Recorder).Header` | Keep | Create independent request-header input to test accidental forwarding or reflection. |
| `(*Recorder).Reader` | Keep | [credential readers](#credential-readers) |

No consumer-facing identifier was removed or merged: each has a working scenario in [the injection tests](../embargotest/inject_test.go), [SDK tests](../tests/integrations_test.go), [database tests](../input_test.go), [JSON tests](../json_test.go) or [value checks](../embargotest/value_test.go). An application can always construct a header or reader from Canary itself; these methods keep fixture input tied to the Recorder's configured canary and lifecycle. They do not add alternative scanning or masking contracts.

Internal detector implementations and output.JSON are exported only across the module's internal package boundary. They do not add consumer constructors or options. Application-owned secret types can use an unexported pointer to prevent fmt from revealing an underlying string field; see [values.md](values.md).

## Table explanations

<a id="sensitive-keys"></a>

Select application field names for slog, JSON and adapters; the same rule also recognizes text assignments. It replaces the key set, as WithKinds replaces the detector set.

<a id="entropy-selection"></a>

Inspect unlabelled random-looking tokens when explicitly requested by WithAll or WithKinds; NewScanner and its zero value omit it. Confidence remains 0.3.

<a id="guard-lifecycle"></a>

Supervise a whole package from TestMain, including its existing stdout, stderr and default logger. Recorder.Run instead names one isolated child helper. Both share Recorder options.

<a id="credential-files"></a>

Supply a credential-file path with private file permissions and test-owned cleanup. Reader cannot exercise a path-based loader.

<a id="credential-readers"></a>

Feed the configured canary into request bodies or config parsers accepting io.Reader, without mutable sharing with the Recorder.
