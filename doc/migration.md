# Scanner behavior on unreleased main

The public API signatures are unchanged. The API golden continues to check the exported contract. The default minimum confidence remains 0.

Built-in detectors now decode one layer of valid percent escapes before scanning and return byte offsets into the original input. For example, `a%40example.com` is detected and masking replaces the entire original escaped address. Literal `+`, malformed escapes and other encoding families remain unchanged. Custom detectors still receive the original bytes. Applications that already percent-decode a field should account for the scanner decoding one further layer of the bytes it receives.

PAN, My Number and Japanese phone candidates under attached business labels now score 0.4. Default scanners still return them. Lower scores can also change which kind wins an overlap in `MaskFunc`. Applications using a higher `WithMinConfidence` threshold may stop reporting these candidates, including genuine secrets with misleading labels. A global threshold of 0.7 also excludes bank-account findings and some sort codes; select policies per use case using the [accuracy tables](accuracy.md).

My Number findings embedded in ASCII identifiers are rejected. Scanner ordering, overlap handling, custom detector validation, slog scalar scanning and logger metadata handling retain their contracts.

[Support maintenance](https://github.com/sponsors/nao1215).


## Forgotten credentials

NewScanner and WithAll now include credential assignments, URL/DSN secrets, provider token prefixes and confidence-0.3 entropy candidates. Use explicit WithKinds to keep a narrower policy. Threshold 0 is unchanged on every path; passing WithMinConfidence(0.5) discards entropy candidates and business-label numeric candidates, including true secrets with those characteristics. New credential grammar uses original URL bytes to preserve escaped password delimiters, while older built-ins retain percent decoding. WithSensitiveKeys also controls ordinary text assignments; provider-specific field names and URL credentials remain detector rules.

Complete PEM private keys now produce a span through the matching END marker; incomplete inputs still identify the header. Code consuming exact header spans should account for this intentional extension. IBAN check digits 00, 01 and 99 are now rejected even when the remainder is 1.

Guard supervises a child test process and preserves parent globals, so move TestMain setup with externally visible side effects into the guarded lifecycle as needed; TestMain runs in both supervisor and child. Read [testing output](testing-output.md) for bounds, attribution and subprocess limits. CheckValue can validate a domain-owned type without adding embargo imports to that domain package.
