package detector

import "bytes"

// UKSortCodeDetail holds UK sort code-specific detail information.
type UKSortCodeDetail struct {
	// FormattedValue is the sort code in XX-XX-XX format with hyphens.
	FormattedValue string
}

// UKSortCode detects UK bank sort codes in text.
//
// A UK sort code is a 6-digit number that identifies the bank and branch for
// domestic payments. Sort codes are typically formatted as XX-XX-XX (with
// hyphens) or XX XX XX (with spaces).
//
// Detection logic:
//  1. Scan for the pattern DD-DD-DD or DD DD DD where D is a digit
//  2. Validate that the sequence has exactly 6 digits with consistent separators
//  3. Check word boundaries to avoid matching substrings
//  4. When the pattern looks date-like (middle pair is month 01-12, and at
//     least one outer pair is day 01-31), check for sort code context keywords
//     nearby. If context is found, accept with reduced confidence (0.55).
//     If no context is found, reject the pattern to reduce false positives.
//
// Only formatted sort codes (with hyphens or spaces) are detected. Bare
// 6-digit sequences are indistinguishable from other numeric data and
// would produce too many false positives.
//
// There is no standard checksum for UK sort codes, so confidence is based
// on the formatted pattern match alone.
//
// Confidence:
//   - 0.7 for a non-date-like formatted sort code
//   - 0.55 for a date-like pattern with sort code context keywords nearby
type UKSortCode struct{}

// NewUKSortCode creates a new UK sort code detector.
func NewUKSortCode() *UKSortCode {
	return &UKSortCode{}
}

// Name returns "uk_sortcode".
func (d *UKSortCode) Name() DetectorName {
	return NameUKSortCode
}

// Hints returns byte sequences for pre-filtering.
// Formatted sort codes use either hyphens (XX-XX-XX) or spaces (XX XX XX)
// as separators. Both are included to ensure all valid sort codes pass the
// hint filter. The space hint is very common in text, which reduces filtering
// efficiency, but correctness requires it — omitting it would silently miss
// space-separated sort codes.
func (d *UKSortCode) Hints() [][]byte {
	return [][]byte{
		[]byte("-"),
		[]byte(" "),
	}
}

// Scan examines data for UK sort codes and returns findings.
func (d *UKSortCode) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-7; i++ {
		// Must start with two digits.
		if !isDigit(data[i]) || !isDigit(data[i+1]) {
			continue
		}

		// Third character must be a separator (hyphen or space).
		sep := data[i+2]
		if sep != '-' && sep != ' ' {
			continue
		}

		// Check the remaining pattern: DD<sep>DD<sep>DD.
		if i+7 >= len(data) {
			continue
		}
		if !isDigit(data[i+3]) || !isDigit(data[i+4]) {
			continue
		}
		if data[i+5] != sep {
			continue
		}
		if !isDigit(data[i+6]) || !isDigit(data[i+7]) {
			continue
		}

		end := i + 8

		// Word boundary: preceding character must not be a digit or letter.
		if i > 0 && isAlphaNum(data[i-1]) {
			continue
		}

		// Avoid matching part of a longer separated sequence (e.g., "12-34-56-78").
		if i >= 3 && data[i-1] == sep && isDigit(data[i-2]) && isDigit(data[i-3]) {
			continue
		}

		// Word boundary: following character must not be a digit.
		// Allow letter to follow (e.g., "12-34-56 is the sort code").
		if end < len(data) && isDigit(data[end]) {
			continue
		}

		// Avoid matching patterns that continue with another separator group
		// (e.g., "DD-DD-DD-DD" is part of a longer sequence, not a sort code).
		if end < len(data) && data[end] == sep {
			continue
		}

		// Reject all-zero sort codes (00-00-00). No valid UK sort code
		// has all six digits as zero.
		if data[i] == '0' && data[i+1] == '0' &&
			data[i+3] == '0' && data[i+4] == '0' &&
			data[i+6] == '0' && data[i+7] == '0' {
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
