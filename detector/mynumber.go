package detector

// MyNumberDetail holds My Number-specific detail information.
type MyNumberDetail struct {
	// CheckDigitValid indicates whether the check digit (12th digit) is valid
	// according to the MOD 11 algorithm.
	CheckDigitValid bool
}

// MyNumber detects Japanese My Number (individual number) in text.
//
// My Number is a 12-digit number assigned to every resident of Japan.
// The last digit is a check digit calculated from the first 11 digits.
//
// Check digit algorithm:
//  1. For each of the first 11 digits (P[0] to P[10], from left to right):
//     Calculate weight Q[n] where n is the position from the right (0-indexed).
//     Q[n] = n + 2 if n < 6, or Q[n] = n - 4 if n >= 6.
//  2. Sum = P[10-n] * Q[n] for n = 0..10
//  3. Remainder = Sum mod 11
//  4. Check digit = 0 if remainder <= 1, else 11 - remainder
//
// Confidence: 0.95 when the check digit is valid.
type MyNumber struct{}

// NewMyNumber creates a new My Number detector.
func NewMyNumber() *MyNumber {
	return &MyNumber{}
}

// Name returns "mynumber".
func (d *MyNumber) Name() DetectorName {
	return NameMyNumber
}

// Hints returns nil, causing the Scanner to always run My Number detection.
// My Number consists of digits 0-9 only and can start with any digit,
// so listing all ten single-digit hints would match virtually every input.
// Returning nil makes this intent explicit. The Scan method itself performs
// fast rejection (12-digit length + check digit) so the cost of always
// scanning is negligible.
func (d *MyNumber) Hints() [][]byte {
	return nil
}

// Scan examines data for My Number values and returns findings.
// It normalizes full-width digits before scanning.
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
		if !isDigit(data[i]) {
			i++
			continue
		}

		// Check that this digit is not part of a longer alphanumeric token.
		if i > 0 && isAlpha(data[i-1]) {
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
