package detect

import "github.com/nao1215/embargo/internal/ascii"

// ABARouting implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindABARouting.
type ABARouting struct{}

// NewABARouting combines US routing-prefix ranges with the weighted checksum.
func NewABARouting() *ABARouting {
	return &ABARouting{}
}

// Name returns "aba_routing".
func (d *ABARouting) Name() DetectorName {
	return NameABARouting
}

// Hints returns nil because no selective exhaustive substring is available.
func (d *ABARouting) Hints() [][]byte {
	return nil
}

// startBytes reports that every candidate contains an ASCII or full-width digit.
func (d *ABARouting) startBytes() []byte { return digitStarts() }

// Scan returns matches in data using the rules documented on [ABARouting].
func (d *ABARouting) Scan(data []byte) []Finding {
	normalized, posMap := normalizeDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized scans the normalized (ASCII) byte slice for ABA routing numbers.
func (d *ABARouting) scanNormalized(orig, data []byte, posMap []int) []Finding {
	return scanNumeric(orig, data, posMap, d.candidate, false)
}

// abaDigits is the length of a routing number.
const abaDigits = 9

// candidate checks the nine-digit run that may start at i at a word boundary
// and returns where scanning continues.
func (d *ABARouting) candidate(orig, data []byte, posMap []int, i int) (Finding, int, bool) {
	if !ascii.IsDigit(data[i]) || !abaWordStart(orig, data, posMap, i) {
		return Finding{}, i + 1, false
	}
	end := i
	for end < len(data) && ascii.IsDigit(data[end]) {
		end++
	}
	if end-i != abaDigits || !validABACandidate(data, i, end) || recordLabeled(data, i, "routing", "aba", "rtn") {
		return Finding{}, end, false
	}
	//nolint:mnd // The detector contract documents this heuristic score.
	return viewFinding(d.Name(), posMap, i, end, 0.85), end, true
}

// normalizedEscapeSeparator reports whether the percent escape at i of a
// normalized view of length n decodes to a documented separator, so its three
// bytes are skipped as a unit. Callers test the '%' byte first.
func normalizedEscapeSeparator(orig []byte, posMap []int, n, i int) bool {
	//nolint:mnd // A percent escape occupies three bytes.
	return i+3 <= n && encodedSeparatorBefore(orig, originalPosition(posMap, i+3))
}

// abaWordStart reports whether a digit at i begins a word: the preceding byte
// is not alphanumeric unless an encoded separator precedes the original byte.
func abaWordStart(orig, data []byte, posMap []int, i int) bool {
	return leadingBoundaryView(orig, posMap, data, i, ascii.IsAlphaNum)
}

// validateABAChecksum validates the ABA routing number checksum.
// The formula is: 3*(d1+d4+d7) + 7*(d2+d5+d8) + (d3+d6+d9) ≡ 0 (mod 10)
// where d1..d9 are the 9 digits of the routing number.
func validateABAChecksum(digits []byte) bool {
	if len(digits) != abaDigits {
		return false
	}

	sum := 3*(int(digits[0]-'0')+int(digits[3]-'0')+int(digits[6]-'0')) +
		7*(int(digits[1]-'0')+int(digits[4]-'0')+int(digits[7]-'0')) +
		(int(digits[2]-'0') + int(digits[5]-'0') + int(digits[8]-'0'))

	return sum%10 == 0
}

// validABAPrefix checks the Federal Reserve routing symbol without building a district label.
// Valid ranges are 01-12, 21-32, 61-72, and 80.
func validABAPrefix(digits []byte) bool {
	//nolint:mnd // A Federal Reserve routing symbol has two decimal digits.
	if len(digits) < 2 {
		return false
	}
	//nolint:mnd // Two decimal digits encode the Federal Reserve routing symbol.
	prefix := int(digits[0]-'0')*10 + int(digits[1]-'0')
	return prefix >= 1 && prefix <= 12 || prefix >= 21 && prefix <= 32 || prefix >= 61 && prefix <= 72 || prefix == 80
}

// validABACandidate checks numeric/log boundaries, routing prefix and checksum.
func validABACandidate(data []byte, i, end int) bool {
	// A decimal component (including an RFC3339 fractional second) is not
	// a standalone routing number, even when its digits satisfy the checksum.
	if i >= 2 && data[i-1] == '.' && ascii.IsDigit(data[i-2]) || end+1 < len(data) && data[end] == '.' && ascii.IsDigit(data[end+1]) {
		return false
	}

	if exceptionCounter(data, end) || logSequence(data, i) {
		return false
	}

	digits := data[i:end]

	// Validate Federal Reserve routing symbol (first two digits).
	if !validABAPrefix(digits) {
		return false
	}

	// Word boundary: following character must not be alphanumeric.
	if end < len(data) && ascii.IsAlphaNum(data[end]) {
		return false
	}

	// Validate ABA checksum. Numbers that fail the checksum are
	// unconditionally rejected to prevent false positives in
	// financial contexts.
	if !validateABAChecksum(digits) || operationalNumberContext(data, i) {
		return false
	}
	return true
}
