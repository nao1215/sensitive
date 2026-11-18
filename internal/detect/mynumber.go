package detect

import (
	"github.com/nao1215/embargo/internal/ascii"
)

// MyNumber implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindMyNumber.
type MyNumber struct{}

// NewMyNumber validates the weighted MOD 11 check digit after digit normalization.
func NewMyNumber() *MyNumber {
	return &MyNumber{}
}

// Name returns "mynumber".
func (d *MyNumber) Name() DetectorName {
	return NameMyNumber
}

// Hints returns nil because no selective exhaustive substring is available.
func (d *MyNumber) Hints() [][]byte {
	return nil
}

// startBytes reports that every candidate contains an ASCII or full-width digit.
func (d *MyNumber) startBytes() []byte { return digitStarts() }

// Scan returns matches in data using the rules documented on [MyNumber].
func (d *MyNumber) Scan(data []byte) []Finding {
	normalized, posMap := normalizeDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized performs My Number detection on normalized data.
// orig is the original (possibly full-width) input used for matched text.
func (d *MyNumber) scanNormalized(orig, data []byte, posMap []int) []Finding {
	var findings []Finding
	var logContext numericLogContext

	i := 0
	for i < len(data) {
		if data[i] == '%' && normalizedEscapeSeparator(orig, posMap, len(data), i) {
			i += 3
			continue
		}
		if !ascii.IsDigit(data[i]) {
			i++
			continue
		}

		// Check that this digit is not part of a longer alphanumeric token.
		if !normalizedIdentifierStart(orig, data, posMap, i) {
			i++
			continue
		}

		// Extract digits, allowing '-' and ' ' as separators.
		start := i
		digits, end := appendSeparatedDigits(data, start, make([]byte, 0, phoneDigitCapacity), cardSeparator)

		// Must be exactly 12 digits, not followed by more digits.
		if !myNumberWhole(data, digits, end) {
			i = end
			continue
		}

		if isValidMyNumber(digits) && !logContext.fragment(data, start, end) && !arnAccount(data, start, end) && !identifierLabeled(data, start) {
			//nolint:mnd // The detector contract documents this heuristic score.
			findings = append(findings, labeledViewFinding(d.Name(), orig, posMap, start, end, 0.95))
		}
		i = end
	}

	return findings
}

// normalizedIdentifierStart reports whether position i of a normalized view
// starts an identifier: the preceding byte is not an identifier byte unless an
// encoded separator precedes the original byte.
func normalizedIdentifierStart(orig, data []byte, posMap []int, i int) bool {
	return leadingBoundaryView(orig, posMap, data, i, isIdentifierByte)
}

// myNumberWhole reports whether a candidate has exactly 12 digits and is not
// followed by an identifier byte.
func myNumberWhole(data, digits []byte, end int) bool {
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(digits) != 12 {
		return false
	}
	return end >= len(data) || !isIdentifierByte(data[end])
}

// isValidMyNumber validates a 12-digit My Number using the check digit algorithm.
//
// The algorithm processes the first 11 digits with position-based weights:
//
//	Position from right (n): 0  1  2  3  4  5  6  7  8  9  10
//	Weight (Q[n]):           2  3  4  5  6  7  2  3  4  5  6
//
// The check digit (12th digit) must equal:
//   - 0 if (sum mod 11) <= 1
//   - 11 - (sum mod 11) otherwise
func isValidMyNumber(digits []byte) bool {
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(digits) != 12 {
		return false
	}
	sum := 0
	for i := range 11 {
		p := int(digits[10-i] - '0')
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		q := i + 2
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if i >= 6 {
			q -= 6
		}
		sum += p * q
	}
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	remainder := sum % 11
	var expected int
	if remainder <= 1 {
		expected = 0
	} else {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		expected = 11 - remainder
	}
	actual := int(digits[11] - '0')
	return actual == expected
}
