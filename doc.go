// Package embargo detects and masks sensitive text inside a Go program.
// Use [NewScanner] and [Mask] for text, [NewSlogHandler] for runtime logs,
// and [NewSecret] for values that should print as [REDACTED].
//
// # Scanning
//
// NewScanner and a zero-value Scanner omit unlabelled entropy tokens; [WithAll] includes them.
// [WithKinds] narrows that selection; [WithDetector] adds an application pattern.
// Findings contain original byte positions and retain overlaps. [MaskFunc]
// supports custom replacements, such as keeping a card's last four digits.
//
// # Values and output
//
// [Secret] hides supported formatted and encoded representations; [Secret.Reveal]
// deliberately exposes the value. [Input] decodes strings or bytes into a Secret
// snapshot. These types do not erase memory.
//
// The embargotest package captures real log, HTTP and child-process output in
// tests. It checks a known fake secret, detector findings and expected content.
//
// See the [detector cases] and [output examples] for supported representations.
//
// [detector cases]: https://github.com/nao1215/embargo/blob/main/doc/accuracy.md
// [output examples]: https://nao1215.github.io/embargo/getting-started/#fail-tests-on-leaks
package embargo
