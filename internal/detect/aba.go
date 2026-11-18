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
func (d *ABARouting) startBytes() []byte { return digitStarts }

// Scan returns matches in data using the rules documented on [ABARouting].
func (d *ABARouting) Scan(data []byte) []Finding {
	normalized, posMap := normalizeDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized scans the normalized (ASCII) byte slice for ABA routing numbers.
func (d *ABARouting) scanNormalized(orig, data []byte, posMap []int) []Finding {
	var findings []Finding

	for i := 0; i < len(data); i++ {
		// Escape bytes cannot become part of a numeric candidate.
		if data[i] == '%' && normalizedEscapeSeparator(orig, posMap, len(data), i) {
			i += 2
			continue
		}
		if !ascii.IsDigit(data[i]) {
			continue
		}

		// Word boundary: preceding character must not be alphanumeric.
		if !abaWordStart(orig, data, posMap, i) {
			continue
		}

		// Need exactly 9 consecutive digits.
		end := i
		for end < len(data) && ascii.IsDigit(data[end]) {
			end++
		}
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if end-i != 9 {
			i = end - 1
			continue
		}

		if !validABACandidate(data, i, end) {
			i = end - 1
			continue
		}
		confidence := 0.85

		origStart, origEnd := mapOriginalRange(posMap, i, end)

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        origStart,
			End:          origEnd,
			Confidence:   confidence,
		})

		i = end - 1
	}

	return findings
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
	return i == 0 || !ascii.IsAlphaNum(data[i-1]) || encodedSeparatorBefore(orig, originalPosition(posMap, i))
}

// validateABAChecksum validates the ABA routing number checksum.
// The formula is: 3*(d1+d4+d7) + 7*(d2+d5+d8) + (d3+d6+d9) ≡ 0 (mod 10)
// where d1..d9 are the 9 digits of the routing number.
func validateABAChecksum(digits []byte) bool {
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(digits) != 9 {
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
