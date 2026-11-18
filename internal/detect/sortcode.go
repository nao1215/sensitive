package detect

import (
	"github.com/nao1215/embargo/internal/ascii"
)

// UKSortCode implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindUKSortCode.
type UKSortCode struct{}

// NewUKSortCode requires separators and context only for date-like candidates.
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
	if !ascii.IsDigit(data[i]) || !ascii.IsDigit(data[i+1]) {
		return 0, false
	}

	sep = data[i+2]
	if sep != '-' && sep != ' ' {
		return 0, false
	}

	if i+7 >= len(data) {
		return 0, false
	}
	if !ascii.IsDigit(data[i+3]) || !ascii.IsDigit(data[i+4]) {
		return 0, false
	}
	if data[i+5] != sep {
		return 0, false
	}
	if !ascii.IsDigit(data[i+6]) || !ascii.IsDigit(data[i+7]) {
		return 0, false
	}

	return sep, true
}

// isValidSortCodeBoundary checks word boundaries around a candidate sort code
// at data[i:end] using the given separator. It returns false if the candidate
// is preceded by an alphanumeric character, is part of a longer separated
// sequence, is followed by a digit, or continues with another separator group.
func isValidSortCodeBoundary(data []byte, i, end int, sep byte) bool {
	return sortCodeLeadingBoundary(data, i, sep) && sortCodeTrailingBoundary(data, end, sep)
}

// sortCodeLeadingBoundary rejects a candidate preceded by an alphanumeric byte
// or by another separated digit pair.
func sortCodeLeadingBoundary(data []byte, i int, sep byte) bool {
	// Word boundary: preceding character must not be a digit or letter.
	if !leadingBoundary(data, i, ascii.IsAlphaNum) {
		return false
	}

	// Avoid matching part of a longer separated sequence (e.g., "12-34-56-78").
	return i < 3 || data[i-1] != sep || !ascii.IsDigit(data[i-2]) || !ascii.IsDigit(data[i-3])
}

// sortCodeTrailingBoundary rejects a candidate followed by a digit or by
// another separator group, except a hyphenated code after a space.
func sortCodeTrailingBoundary(data []byte, end int, sep byte) bool {
	// Word boundary: following character must not be a digit.
	// Allow letter to follow (e.g., "12-34-56 is the sort code").
	if end < len(data) && ascii.IsDigit(data[end]) {
		return false
	}

	// Avoid matching patterns that continue with another separator group
	// (e.g., "DD-DD-DD-DD" is part of a longer sequence, not a sort code).
	// A space can also delimit prose or end the input; reject it only when
	// another numeric group follows.
	if end < len(data) && data[end] == sep &&
		(sep != ' ' || end+1 < len(data) && ascii.IsDigit(data[end+1])) {
		// A complete hyphenated code following a space is an independent
		// token, not another pair in the space-separated candidate.
		if sep == ' ' && end+8 < len(data) {
			next, ok := isSortCodePattern(data, end+1)
			if ok && next == '-' {
				return true
			}
		}
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

		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   confidence,
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
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	middle := int(d2h-'0')*10 + int(d2l-'0')
	if middle < 1 || middle > 12 {
		return false
	}

	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	first := int(d1h-'0')*10 + int(d1l-'0')
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	return containsFoldNear(data, start, end, 40, sortCodeContextKeywords)
}

// sortCodeContextKeywords are keywords that indicate a sort code context.
// They are lowercase because containsFoldNear folds only the data. The table
// is read-only.
var sortCodeContextKeywords = [][]byte{
	[]byte("sort code"),
	[]byte("sort-code"),
	[]byte("sortcode"),
	[]byte("sort_code"),
	[]byte("sc:"),
	[]byte("bacs"),
}
