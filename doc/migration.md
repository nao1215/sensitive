# Scanner behavior changes in v0.4.0

The public API signatures are unchanged. The API golden continues to check the exported contract. The default minimum confidence remains 0.

Built-in detectors now decode one layer of valid percent escapes before scanning and return byte offsets into the original input. For example, `a%40example.com` is detected and masking replaces the entire original escaped address. Literal `+`, malformed escapes and other encoding families remain unchanged. Custom detectors still receive the original bytes. Applications that already percent-decode a field should account for the scanner decoding one further layer of the bytes it receives.

PAN, My Number and Japanese phone candidates under attached business labels now score 0.4. Default scanners still return them. Lower scores can also change which kind wins an overlap in `MaskFunc`. Applications using a higher `WithMinConfidence` threshold may stop reporting these candidates, including genuine secrets with misleading labels. A global threshold of 0.7 also excludes bank-account findings and some sort codes; select policies per use case using the [accuracy tables](accuracy.md).

My Number findings embedded in ASCII identifiers are rejected. Scanner ordering, overlap handling, custom detector validation, slog scalar scanning and logger metadata handling retain their contracts.

[Support maintenance](https://github.com/sponsors/nao1215).


## Forgotten credentials

NewScanner and WithAll now include credential assignments, URL/DSN secrets, provider token prefixes and confidence-0.3 entropy candidates. Use explicit WithKinds to keep a narrower policy. Threshold 0 is unchanged on every path; passing WithMinConfidence(0.5) discards entropy candidates and business-label numeric candidates, including true secrets with those characteristics. New credential grammar uses original URL bytes to preserve escaped password delimiters, while older built-ins retain percent decoding. WithSensitiveKeys also controls ordinary text assignments; provider-specific field names and URL credentials remain detector rules.

Complete PEM private keys now produce a span through the matching END marker; incomplete inputs still identify the header. Code consuming exact header spans should account for this intentional extension. IBAN check digits 00, 01 and 99 are now rejected even when the remainder is 1.

Guard supervises a child test process and preserves parent globals, so move TestMain setup with externally visible side effects into the guarded lifecycle as needed; TestMain runs in both supervisor and child. Read [testing output](testing-output.md) for bounds, attribution and subprocess limits. CheckValue can validate a domain-owned type without adding embargo imports to that domain package.

## After v0.4.0: log evidence and value checks

NewScanner and the zero Scanner now omit KindHighEntropy. To retain every v0.4.0 detector, construct `embargo.NewScanner(embargo.WithAll())`; to select only the entropy heuristic, use `WithKinds(KindHighEntropy)`. Minimum confidence remains zero, and the heuristic still reports 0.3. Unlabelled random secrets therefore require explicit entropy selection; key-based credentials and provider prefixes remain in the default set. This selection also applies to the default Recorder and Guard scanners.

Entropy candidates stop at `/` and are rejected next to path separators or dotted name components. SWIFT ignores path and hostname components; PAN, MyNumber and Japanese phone detection reject decimal tails and numeric hostname fragments. PAN also rejects the signed suffix of an underscore-delimited identifier. ABA skips explicit eventTime/downTime/lock/ino assignments, and the token assignment rule omits unquoted Java object references. These rules can miss secrets deliberately placed in those positions; quoted token strings and password/secret assignments retain masking. The [real-log evaluation](accuracy.md#public-system-logs) records both improvements and held-out errors left unchanged.

`fmt.Sprintf("%#v", secret)` and `secret.GoString()` now include the instantiated type, such as `embargo.Secret[string]([REDACTED])`. Update exact string assertions; ordinary formatting, JSON and text encoding still write the marker. Input keeps its existing marker-only format.

CheckValue now inspects unexported struct fields through fmt. A defined string with output methods can fail this check because fmt bypasses those methods in that position. Use Secret or an application-owned struct containing an unexported pointer, as shown in [values.md](values.md). All twelve round 11–12 public identifiers remain available; [the API review](api-review.md) records their callers and boundaries.
