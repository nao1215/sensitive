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

// cardSeparator reports the separators PAN and My Number allow between digits.
func cardSeparator(b byte) bool { return b == '-' || b == ' ' }

// phoneSeparator reports the separators Japanese phone numbers allow between digits.
func phoneSeparator(b byte) bool { return b == '-' || b == '(' || b == ')' || b == ' ' }
