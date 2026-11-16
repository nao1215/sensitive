package detect

import "bytes"

// MyNumberDetail holds My Number-specific detail information.
type MyNumberDetail struct {
	// CheckDigitValid indicates whether the check digit (12th digit) is valid
	// according to the MOD 11 algorithm.
	CheckDigitValid bool
}

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

// Scan returns matches in data using the rules documented on [MyNumber].
func (d *MyNumber) Scan(data []byte) []Finding {
	normalized, posMap := normalizeDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized performs My Number detection on normalized data.
// orig is the original (possibly full-width) input used for RawValue.
func (d *MyNumber) scanNormalized(orig, data []byte, posMap []int) []Finding {
	var findings []Finding
	var logContext numericLogContext

	i := 0
	for i < len(data) {
		//nolint:mnd // A percent escape occupies three bytes.
		if data[i] == '%' && i+3 <= len(data) && encodedSeparatorBefore(orig, originalPosition(posMap, i+3)) {
			i += 3
			continue
		}
		if !isDigit(data[i]) {
			i++
			continue
		}

		// Check that this digit is not part of a longer alphanumeric token.
		if i > 0 && isPhoneWordChar(data[i-1]) && !encodedSeparatorBefore(orig, originalPosition(posMap, i)) {
			i++
			continue
		}

		// Extract digits, allowing '-' and ' ' as separators.
		start := i
		digits, end := extractMyNumberDigits(data, start)

		// Must be exactly 12 digits, not followed by more digits.
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if len(digits) != 12 {
			i = end
			continue
		}
		if end < len(data) && isPhoneWordChar(data[end]) {
			i = end
			continue
		}

		if isValidMyNumber(digits) && !logContext.fragment(data, start, end) && !arnAccount(data, start, end) {
			origStart, origEnd := mapOriginalRange(posMap, start, end)

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        origStart,
				End:          origEnd,
				//nolint:mnd // The detector contract documents this heuristic score.
				Confidence: businessConfidence(orig, origStart, 0.95),
				RawValue:   string(orig[origStart:origEnd]),
				Detail:     &MyNumberDetail{CheckDigitValid: true},
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

// ARN has partition, service, region and account fields before its resource.
func arnAccount(data []byte, start, end int) bool {
	if end >= len(data) || data[end] != ':' {
		return false
	}
	left := start
	colons := 0
	for left > 0 && !urlDelimiter(data[left-1]) && data[left-1] != '=' && data[left-1] != '[' {
		left--
		if data[left] == ':' {
			colons++
			const arnSeparators = 4
			if colons == arnSeparators {
				left = max(0, left-len("arn"))
				break
			}
		}
	}
	if left > 0 && isAlphaNum(data[left-1]) {
		return false
	}
	fields := bytes.Split(data[left:start], []byte(":"))
	return len(fields) == 5 && string(fields[0]) == "arn" && len(fields[1]) > 0 && len(fields[2]) > 0 && len(fields[4]) == 0
}
