package detect

import "github.com/nao1215/embargo/internal/ascii"

// hasDigits reports whether data contains at least n ASCII digits.
func hasDigits(data []byte, n int) bool {
	count := 0
	for _, b := range data {
		if ascii.IsDigit(b) {
			count++
			if count == n {
				return true
			}
		}
	}
	return false
}

// hasDigitRun reports whether data holds n consecutive ASCII digits, such as
// the four-digit line every number ends with.
func hasDigitRun(data []byte, n int) bool {
	run := 0
	for _, b := range data {
		if !ascii.IsDigit(b) {
			run = 0
			continue
		}
		run++
		if run == n {
			return true
		}
	}
	return false
}

// allDigits reports whether every byte of data is an ASCII digit.
func allDigits(data []byte) bool {
	for _, b := range data {
		if !ascii.IsDigit(b) {
			return false
		}
	}
	return true
}

// appendSeparatedDigits appends the digits of the run starting at data[start]
// to digits. The run holds digits and bytes for which separator is true; end is
// just after its last digit, so trailing separators stay outside the candidate.
func appendSeparatedDigits(data []byte, start int, digits []byte, separator func(byte) bool) (run []byte, end int) {
	j := start
	for j < len(data) && (ascii.IsDigit(data[j]) || separator(data[j])) {
		if ascii.IsDigit(data[j]) {
			digits = append(digits, data[j])
		}
		j++
	}
	end = j
	for end > start && !ascii.IsDigit(data[end-1]) {
		end--
	}
	return digits, end
}

// hasWideDigits reports whether data holds at least n digits, counting the
// full-width forms that the numeric detectors normalize as well as ASCII.
func hasWideDigits(data []byte, n int) bool {
	count := 0
	for i := 0; i < len(data) && count < n; i++ {
		if ascii.IsDigit(data[i]) || fullWidthDigitAt(data, i) {
			count++
		}
	}
	return count >= n
}

// fullWidthDigitAt reports whether a full-width digit, U+FF10 to U+FF19,
// starts at i.
func fullWidthDigitAt(data []byte, i int) bool {
	return data[i] == 0xef && i+2 < len(data) && data[i+1] == 0xbc && data[i+2] >= 0x90 && data[i+2] <= 0x99
}

// Fewest digits of each numeric kind: a value with fewer holds no candidate.
const (
	jpPhoneMinDigits = 10
	myNumberDigits   = 12
	sortCodeDigits   = 6
)

func (d *PAN) hasCandidate(value []byte) bool        { return hasWideDigits(value, panMinDigits) }
func (d *MyNumber) hasCandidate(value []byte) bool   { return hasWideDigits(value, myNumberDigits) }
func (d *JPPhone) hasCandidate(value []byte) bool    { return hasWideDigits(value, jpPhoneMinDigits) }
func (d *USPhone) hasCandidate(value []byte) bool    { return hasWideDigits(value, usPhoneDigits) }
func (d *ABARouting) hasCandidate(value []byte) bool { return hasWideDigits(value, abaDigits) }
func (d *UKSortCode) hasCandidate(value []byte) bool { return hasWideDigits(value, sortCodeDigits) }

// numericCandidate checks the number that may start at normalized index i
// and returns its finding, whether it is one, and where scanning continues:
// after i, and at the number's end when it is one.
type numericCandidate func(orig, data []byte, posMap []int, i int) (Finding, int, bool)

// scanNumeric walks a normalized view and collects candidate findings. A
// percent escape of a separator is skipped as a unit, since its bytes cannot
// belong to a number. With logFragments, a number that is a fragment of a log
// value, such as a decimal tail or a hostname component, is not a finding.
func scanNumeric(orig, data []byte, posMap []int, candidate numericCandidate, logFragments bool) []Finding {
	var findings []Finding
	var logContext numericLogContext
	for i := numericStart(data, 0); i < len(data); i = numericStart(data, i) {
		if data[i] == '%' && normalizedEscapeSeparator(orig, posMap, len(data), i) {
			i += len("%20")
			continue
		}
		f, next, ok := candidate(orig, data, posMap, i)
		if ok && (!logFragments || !logContext.fragment(data, i, next)) {
			findings = append(findings, f)
		}
		i = next
	}
	return findings
}

// numericStart returns the first index from i that can start a numeric
// candidate or a percent escape: a digit, '+' for international phone
// numbers, or '%'. Skipping other bytes here keeps the per-candidate call off
// the bytes of words and punctuation.
func numericStart(data []byte, i int) int {
	for i < len(data) && !ascii.IsDigit(data[i]) && data[i] != '+' && data[i] != '%' {
		i++
	}
	return i
}

// cardSeparator reports the separators PAN and My Number allow between digits.
func cardSeparator(b byte) bool { return b == '-' || b == ' ' }

// phoneSeparator reports the separators Japanese phone numbers allow between digits.
func phoneSeparator(b byte) bool { return b == '-' || b == '(' || b == ')' || b == ' ' }
