package detector

import "bytes"

// UKSortCodeDetail holds UK sort code-specific detail information.
type UKSortCodeDetail struct {
	// FormattedValue is the sort code in XX-XX-XX format with hyphens.
	FormattedValue string
}

// UKSortCode detects formatted UK bank/branch identifiers without a checksum or assignment check.
//
//  1. Extract DD-DD-DD or DD DD DD with consistent separators; reject all-zero codes, bare six-digit numbers, and candidates inside longer numeric groups.
//  2. Treat a middle pair in 01–12 with either outer pair in 01–31 as date-like; require nearby sort-code context for these candidates and score them as 0.55.
//  3. Score other formatted matches as 0.7.
type UKSortCode struct{}

// NewUKSortCode creates a new UK sort code detector.
func NewUKSortCode() *UKSortCode {
	return &UKSortCode{}
}

// Name returns "uk_sortcode".
func (d *UKSortCode) Name() DetectorName {
	return NameUKSortCode
}

// Hints returns the pre-filter substrings for [UKSortCode].
func (d *UKSortCode) Hints() [][]byte {
	return [][]byte{
		[]byte("-"),
		[]byte(" "),
	}
}

// isSortCodePattern checks whether data starting at position i matches the
// DD<sep>DD<sep>DD structure where <sep> is a hyphen or space. It returns the
// separator byte and true when the pattern is valid. The caller must ensure
// that i+1 < len(data) before calling.
func isSortCodePattern(data []byte, i int) (sep byte, ok bool) {
	if !isDigit(data[i]) || !isDigit(data[i+1]) {
		return 0, false
	}

	sep = data[i+2]
	if sep != '-' && sep != ' ' {
		return 0, false
	}

	if i+7 >= len(data) {
		return 0, false
	}
	if !isDigit(data[i+3]) || !isDigit(data[i+4]) {
		return 0, false
	}
	if data[i+5] != sep {
		return 0, false
	}
	if !isDigit(data[i+6]) || !isDigit(data[i+7]) {
		return 0, false
	}

	return sep, true
}

// isValidSortCodeBoundary checks word boundaries around a candidate sort code
// at data[i:end] using the given separator. It returns false if the candidate
// is preceded by an alphanumeric character, is part of a longer separated
// sequence, is followed by a digit, or continues with another separator group.
func isValidSortCodeBoundary(data []byte, i, end int, sep byte) bool {
	// Word boundary: preceding character must not be a digit or letter.
	if i > 0 && isAlphaNum(data[i-1]) && !encodedSeparatorBefore(data, i) {
		return false
	}

	// Avoid matching part of a longer separated sequence (e.g., "12-34-56-78").
	if i >= 3 && data[i-1] == sep && isDigit(data[i-2]) && isDigit(data[i-3]) {
		return false
	}

	// Word boundary: following character must not be a digit.
	// Allow letter to follow (e.g., "12-34-56 is the sort code").
	if end < len(data) && isDigit(data[end]) {
		return false
	}

	// Avoid matching patterns that continue with another separator group
	// (e.g., "DD-DD-DD-DD" is part of a longer sequence, not a sort code).
	// A space can also delimit prose or end the input; reject it only when
	// another numeric group follows.
	if end < len(data) && data[end] == sep &&
		(sep != ' ' || end+1 < len(data) && isDigit(data[end+1])) {
		return false
	}

	return true
}

// isAllZeroSortCode checks whether all six digits in the candidate sort code
// starting at position i are zero (i.e. "00-00-00" or "00 00 00"). No valid
// UK sort code has all six digits as zero.
func isAllZeroSortCode(data []byte, i int) bool {
	return data[i] == '0' && data[i+1] == '0' &&
		data[i+3] == '0' && data[i+4] == '0' &&
		data[i+6] == '0' && data[i+7] == '0'
}

// Scan returns matches in data using the rules documented on [UKSortCode].
func (d *UKSortCode) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-7; i++ {
		sep, ok := isSortCodePattern(data, i)
		if !ok {
			continue
		}

		end := i + 8

		if !isValidSortCodeBoundary(data, i, end, sep) {
			continue
		}

		if isAllZeroSortCode(data, i) {
			continue
		}

		confidence := 0.7

		// Date-like pattern check: when the middle pair is a valid month
		// (01-12) and at least one outer pair is a valid day (01-31), the
		// pattern could be a calendar date. If sort code context keywords
		// are nearby, accept with reduced confidence. Otherwise reject.
		if isSortCodeDateLike(data[i], data[i+1], data[i+3], data[i+4], data[i+6], data[i+7]) {
			if !hasSortCodeContext(data, i, end) {
				continue
			}
			confidence = 0.55
		}

		// Build formatted value with hyphens.
		formatted := string([]byte{
			data[i], data[i+1], '-',
			data[i+3], data[i+4], '-',
			data[i+6], data[i+7],
		})

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   confidence,
			RawValue:     string(data[i:end]),
			Detail:       &UKSortCodeDetail{FormattedValue: formatted},
		})

		i = end - 1
	}

	return findings
}

// isSortCodeDateLike reports whether the six digits (given as individual ASCII
// digit bytes d1h,d1l - d2h,d2l - d3h,d3l) form a pattern that looks like a
// calendar date. The check considers two common formats:
//   - YY-MM-DD: middle pair is month (01-12), last pair is day (01-31)
//   - DD-MM-YY: middle pair is month (01-12), first pair is day (01-31)
func isSortCodeDateLike(d1h, d1l, d2h, d2l, d3h, d3l byte) bool {
	middle := int(d2h-'0')*10 + int(d2l-'0')
	if middle < 1 || middle > 12 {
		return false
	}

	first := int(d1h-'0')*10 + int(d1l-'0')
	last := int(d3h-'0')*10 + int(d3l-'0')

	// YY-MM-DD: last pair is a valid day.
	if last >= 1 && last <= 31 {
		return true
	}
	// DD-MM-YY: first pair is a valid day.
	if first >= 1 && first <= 31 {
		return true
	}
	return false
}

// hasSortCodeContext checks for sort code-related keywords near the candidate.
// When a date-like pattern has sort code context, it is accepted with reduced
// confidence rather than being silently rejected.
func hasSortCodeContext(data []byte, start, end int) bool {
	searchStart := start - 40
	if searchStart < 0 {
		searchStart = 0
	}
	searchEnd := end + 40
	if searchEnd > len(data) {
		searchEnd = len(data)
	}
	window := bytes.ToLower(data[searchStart:searchEnd])
	for _, kw := range sortCodeContextKeywords {
		if bytes.Contains(window, kw) {
			return true
		}
	}
	return false
}

// sortCodeContextKeywords are keywords that indicate a sort code context.
// All values are lowercase because the search window is lowered before matching.
var sortCodeContextKeywords = [][]byte{
	[]byte("sort code"),
	[]byte("sort-code"),
	[]byte("sortcode"),
	[]byte("sort_code"),
	[]byte("sc:"),
	[]byte("bacs"),
}
