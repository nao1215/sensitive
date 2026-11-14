package detector

// MyNumberDetail holds My Number-specific detail information.
type MyNumberDetail struct {
	// CheckDigitValid indicates whether the check digit (12th digit) is valid
	// according to the MOD 11 algorithm.
	CheckDigitValid bool
}

// MyNumber detects 12-digit Japanese individual numbers with a valid MOD 11 check digit.
//
//  1. Extract exactly 12 digits; the final digit is the check digit.
//  2. For the first 11 digits, count n from the right starting at 0 and use weight n+2 for n < 6, otherwise n-4; sum digit times weight.
//  3. Let r be the sum modulo 11; require check digit 0 when r <= 1, otherwise 11-r. Score a valid match as 0.95.
type MyNumber struct{}

// NewMyNumber creates a new My Number detector.
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

// Scan returns matches in data using the rules documented on [MyNumber].
func (d *MyNumber) Scan(data []byte) []Finding {
	normalized, posMap := NormalizeFullWidthDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized performs My Number detection on normalized data.
// orig is the original (possibly full-width) input used for RawValue.
func (d *MyNumber) scanNormalized(orig []byte, data []byte, posMap []int) []Finding {
	var findings []Finding

	i := 0
	for i < len(data) {
		if data[i] == '%' && i+3 <= len(data) && encodedSeparatorBefore(orig, posMap[i+3]) {
			i += 3
			continue
		}
		if !isDigit(data[i]) {
			i++
			continue
		}

		// Check that this digit is not part of a longer alphanumeric token.
		if i > 0 && isAlpha(data[i-1]) && !encodedSeparatorBefore(orig, posMap[i]) {
			i++
			continue
		}

		// Extract digits, allowing '-' and ' ' as separators.
		start := i
		digits, end := extractMyNumberDigits(data, start)

		// Must be exactly 12 digits, not followed by more digits.
		if len(digits) != 12 {
			i = end
			continue
		}
		if end < len(data) && isDigit(data[end]) {
			i = end
			continue
		}

		if isValidMyNumber(digits) {
			origStart, origEnd := mapOriginalRange(posMap, start, end)

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        origStart,
				End:          origEnd,
				Confidence:   0.95,
				RawValue:     string(orig[origStart:origEnd]),
				Detail:       &MyNumberDetail{CheckDigitValid: true},
			})
		}
		i = end
	}

	return findings
}

// extractMyNumberDigits extracts digits from data[start:], allowing '-' and ' '
// as separators. Returns the extracted digits and the end position trimmed to
// the last digit (trailing separators are excluded).
func extractMyNumberDigits(data []byte, start int) (digits []byte, end int) {
	j := start
	for j < len(data) && (isDigit(data[j]) || data[j] == '-' || data[j] == ' ') {
		if isDigit(data[j]) {
			digits = append(digits, data[j])
		}
		j++
	}
	end = j
	for end > start && !isDigit(data[end-1]) {
		end--
	}
	return digits, end
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
	if len(digits) != 12 {
		return false
	}
	sum := 0
	for i := range 11 {
		p := int(digits[10-i] - '0')
		q := i + 2
		if i >= 6 {
			q -= 6
		}
		sum += p * q
	}
	remainder := sum % 11
	var expected int
	if remainder <= 1 {
		expected = 0
	} else {
		expected = 11 - remainder
	}
	actual := int(digits[11] - '0')
	return actual == expected
}
