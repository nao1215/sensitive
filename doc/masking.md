# Scanning and masking

`Scan` accepts bytes, `ScanString` accepts text, and `ScanLines` handles independent lines. Findings contain the kind, confidence, and start/end byte positions in the original input. `WithKinds` selects detectors; omitting options enables 26 built-ins at minimum confidence 0, including ambiguous candidates. The 11 national ID kinds and KindHighEntropy are opt-in; `WithAll` selects all 38 built-ins. Built-ins decode one layer of valid percent escapes and map findings back to the original bytes; custom detectors receive the original input. Literal plus signs, malformed escapes and other encodings remain unchanged.

## Overlapping matches

Two detectors can describe overlapping parts of one value. `Mask` replaces their combined range once, so the end of either match cannot escape redaction.

<!-- overlap:start -->
```mermaid
flowchart LR
  input["token=abcdef"] --> first["Match: abcd"]
  input --> second["Match: cdef"]
  first --> union["Merge overlapping spans"]
  second --> union
  union --> output["token=[REDACTED]"]
```
<!-- overlap:end -->

The diagram comes from the [runnable overlap Example](../example_test.go). `make masking-doc` regenerates it and the README before/after table; ordinary tests reject differences.

`MaskFunc` receives the original text of each merged range and chooses its replacement. The highest-confidence finding supplies the kind; ties sort by kind, start, then descending end. Adjacent ranges remain separate; invalid ranges redact the entire input without calling the callback.

`WithMaskFunc` sets the same callback for everything the scanner masks itself: the slog handler, MaskJSON, the HTTP handler and the logger adapters. A support log can then keep the last four digits of a card while other kinds stay hidden. Some values still become `[REDACTED]`, because the callback would see only part of the risk: values under sensitive keys, encoded text that decodes to a finding, a JSON number that a finding covers only in part, and records withheld after a failure. A replacement that contains the value falls back to `[REDACTED]`; one that keeps most of the value, such as all but one digit, is the caller's choice and is not checked. The callback runs concurrently when the scanner is shared, and a panic withholds the record.

See [Mask and MaskFunc Examples](../example_test.go), [overlap tests](../tests/properties_test.go), and [custom detector contracts](../scanner_test.go).

## Custom detection

Implement `Detector.Scan` and pass it to `WithDetector` for an application-specific pattern. Return nonempty ranges within the input and finite confidence values between zero and one. The scanner checks these contracts; custom detectors must leave input unchanged and support concurrent calls when shared.

## Choosing a policy

Confidence is a format heuristic, not a probability that a value is sensitive. For example, a card number under a record label such as order_id or user_id is a lower-confidence candidate. `WithMinConfidence(0.7)` excludes those candidates, including real secrets under misleading labels; it also drops lower-scored bank accounts and some sort codes. Review the [synthetic accuracy cases](accuracy.md) before selecting a threshold or allowing fixture values.

[Support maintenance](https://github.com/sponsors/nao1215).
