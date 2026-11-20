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
	return scanNumeric(nil, orig, data, posMap, d.candidate, true)
}

// candidate checks the 12-digit number that may start at i, allowing '-' and
// ' ' between digits, and returns where scanning continues.
func (d *MyNumber) candidate(orig, data []byte, posMap []int, i int) (Finding, int, bool) {
	// The digit must not continue a longer alphanumeric token.
	if !ascii.IsDigit(data[i]) || !normalizedIdentifierStart(orig, data, posMap, i) {
		return Finding{}, i + 1, false
	}
	digits, end := appendSeparatedDigits(data, i, make([]byte, 0, phoneDigitCapacity), cardSeparator)
	// Must be exactly 12 digits, not followed by more digits.
	if !myNumberWhole(data, digits, end) || !isValidMyNumber(digits) || arnAccount(data, i, end) || identifierLabeled(data, i) {
		return d.split(data, posMap, digits, i, end)
	}
	//nolint:mnd // The detector contract documents this heuristic score.
	return viewFinding(d.Name(), posMap, i, end, 0.95), end, true
}

// split tries a rejected run of digit groups in parts, for a number next to
// the value: the leading 12 digits first, then the run from its next group.
func (d *MyNumber) split(data []byte, posMap []int, digits []byte, start, end int) (Finding, int, bool) {
	group := digitRun(data, start)
	if !splitsRun(group, len(digits), myNumberDigits, myNumberDigits) {
		return Finding{}, end, false
	}
	at := 0
	if leadingGroups(data, start, end, len(digits), myNumberDigits, func(partEnd, count int) bool {
		at = partEnd
		return count == myNumberDigits && isValidMyNumber(digits[:count]) && !arnAccount(data, start, partEnd) && !identifierLabeled(data, start)
	}) {
		//nolint:mnd // The detector contract documents this heuristic score.
		return viewFinding(d.Name(), posMap, start, at, 0.95), at, true
	}
	return Finding{}, start + group, false
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
