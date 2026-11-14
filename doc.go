// Package sensitive detects sensitive data in text; the optional mask subpackage applies masking to its findings.
//
// # Choosing an API
//
// Use [NewScanner] to select detectors, [Scanner.Scan] for bytes, and [Scanner.ScanString] for strings. For readers, [Scanner.ScanReader] handles content that fits in memory and [Scanner.ScanLines] handles line-oriented logs. Each method has a runnable example; its documentation defines offsets, limits, and error behavior.
//
// # Confidence
//
// Confidence is a detector-specific heuristic, not a probability or proof that an identifier is assigned or a credential authenticates. A [WithMinConfidence] threshold of 0.8 selects the high category; 0.4 includes medium confidence. [detector.Finding.Level] supplies the category, and each detector type documents its scoring rules.
//
// Context-based detectors use nearby keywords rather than checksums. In particular, CVV and card expiry can still pass a high-confidence filter; choose detector options to control what is considered sensitive. [WithAll] is useful for exploration, while explicit options suit stricter auditing.
//
// # How It Works
//
//  1. Return immediately for empty input.
//  2. Check cached hints with bytes.Contains, folding ASCII letters for case-insensitive matching; detectors without hints always run.
//  3. Run matching detectors' parsers and domain validation, such as BIN, Luhn, and MOD 97 checks.
//  4. Merge findings using the overlap, ordering, and filtering rules in [Scanner.Scan].
//
// Hint filtering avoids parser work when a required substring is absent; its benefit depends on the input and enabled detectors. See the [benchmarks] for recorded measurements and reproduction commands.
//
// # Custom Detectors
//
// Wrap a compiled pattern with [detector.NewRegex] and pass it to [WithDetector], as its example shows. A specific hint such as TICKET- lets the scanner skip the regex when that substring is absent. For parsing or validation beyond a regex, implement [Detector]; its methods define names, exhaustive hints, and finding offsets. Use dedicated parsers when scan cost matters.
//
// [benchmarks]: https://github.com/nao1215/sensitive/blob/main/doc/benchmarks.md
package sensitive
