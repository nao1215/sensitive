package detector

// CardExpiryDetail holds card expiry date-specific detail information.
type CardExpiryDetail struct {
	// Month is the 2-digit month string (e.g., "01", "12").
	Month string
	// Year is the year string as found in the input (e.g., "25" or "2025").
	Year string
}

// CardExpiry detects payment card expiration dates from context, without checking whether the date is in the future.
//
//  1. Find exp, expir, expiry, expires, expiration, valid thru, valid through, or 有効期限 (ASCII case-insensitive).
//  2. Search up to 50 bytes before and after the keyword for MM/YY, MM/YYYY, MM-YY, or MM-YYYY with month 01–12.
//  3. Reject adjacent digits and previously reported overlaps; return only the date with confidence 0.85.
type CardExpiry struct{}

// NewCardExpiry creates a new card expiry date detector.
func NewCardExpiry() *CardExpiry {
	return &CardExpiry{}
}

// Name returns "card_expiry".
func (d *CardExpiry) Name() DetectorName {
	return NameCardExpiry
}

// Hints returns the pre-filter substrings for [CardExpiry].
func (d *CardExpiry) Hints() [][]byte {
	return [][]byte{
		[]byte("exp"),   // covers Exp, EXP, expiry, expiration, etc.
		[]byte("valid"), // covers Valid, VALID, etc.
		// Japanese: 有効期限
		{0xE6, 0x9C, 0x89, 0xE5, 0x8A, 0xB9, 0xE6, 0x9C, 0x9F, 0xE9, 0x99, 0x90},
	}
}

// Scan returns matches in data using the rules documented on [CardExpiry].
func (d *CardExpiry) Scan(data []byte) []Finding {
	matches := expiryKeywords.findPositions(data)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding
	// used maps the start of each reported date to its end. One place in the
	// text is often matched by several keywords ("exp", "Exp" and "EXP" are
	// all compared case-insensitively), so the same range is searched more
	// than once; searchRange uses this map to skip over dates that are
	// already reported instead of finding a second, overlapping date inside
	// them.
	used := make(map[int]int)

	for _, m := range matches {
		// Search within a 50-byte radius before the keyword for date patterns.
		beforeStart := m.start - 50
		if beforeStart < 0 {
			beforeStart = 0
		}
		d.searchRange(data, beforeStart, m.start, used, &findings)

		// Search within a 50-byte radius after the keyword for date patterns.
		afterEnd := m.end + 50
		if afterEnd > len(data) {
			afterEnd = len(data)
		}
		d.searchRange(data, m.end, afterEnd, used, &findings)
	}

	return findings
}

// expiryCandidate holds a parsed expiry date pattern.
type expiryCandidate struct {
	dateEnd  int
	monthStr string
	yearStr  string
}

// parseExpiryCandidate checks whether data[i:] starts with a valid MM/YY or
// MM/YYYY pattern. Returns the parsed candidate and true, or false if invalid.
func parseExpiryCandidate(data []byte, i int) (expiryCandidate, bool) {
	if !isDigit(data[i]) || !isDigit(data[i+1]) {
		return expiryCandidate{}, false
	}
	sep := data[i+2]
	if sep != '/' && sep != '-' {
		return expiryCandidate{}, false
	}
	if i+5 > len(data) {
		return expiryCandidate{}, false
	}
	if !isDigit(data[i+3]) || !isDigit(data[i+4]) {
		return expiryCandidate{}, false
	}

	dateEnd := i + 5
	if i+7 <= len(data) && isDigit(data[i+5]) && isDigit(data[i+6]) {
		dateEnd = i + 7
	}

	month := int(data[i]-'0')*10 + int(data[i+1]-'0')
	if month < 1 || month > 12 {
		return expiryCandidate{}, false
	}

	monthStr := string(data[i : i+2])
	var yearStr string
	if dateEnd == i+7 {
		yearStr = string(data[i+3 : i+7])
	} else {
		yearStr = string(data[i+3 : i+5])
	}

	return expiryCandidate{dateEnd: dateEnd, monthStr: monthStr, yearStr: yearStr}, true
}

// searchRange scans data[start:end] for card expiry date patterns (MM/YY,
// MM/YYYY, MM-YY, MM-YYYY) and appends any valid findings to results.
// The used map (start to end of each reported date) makes the result
// independent of how many times a range is searched: a position inside an
// already-reported date is skipped past, exactly as a single search skips
// past a date it has just reported, and a date that would overlap a reported
// one is not reported.
func (d *CardExpiry) searchRange(data []byte, start, end int, used map[int]int, results *[]Finding) {
	for i := start; i < end-4; i++ {
		if reportedEnd, ok := reportedDateAt(used, i); ok {
			i = reportedEnd - 1
			continue
		}
		c, ok := parseExpiryCandidate(data, i)
		if !ok {
			continue
		}

		// Word boundary: no digit before or after.
		if i > 0 && isDigit(data[i-1]) && !encodedSeparatorBefore(data, i) {
			continue
		}
		if c.dateEnd < len(data) && isDigit(data[c.dateEnd]) {
			continue
		}

		if overlapsReportedDate(used, i, c.dateEnd) {
			continue
		}
		used[i] = c.dateEnd

		*results = append(*results, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          c.dateEnd,
			Confidence:   0.85,
			RawValue:     string(data[i:c.dateEnd]),
			Detail: &CardExpiryDetail{
				Month: c.monthStr,
				Year:  c.yearStr,
			},
		})

		i = c.dateEnd - 1
	}
}

// maxExpiryLen is the length of the longest date searchRange reports (MM/YYYY).
const maxExpiryLen = 7

// reportedDateAt reports whether position i lies inside a date already in
// used, and if so returns that date's end.
func reportedDateAt(used map[int]int, i int) (int, bool) {
	for s := max(0, i-maxExpiryLen+1); s <= i; s++ {
		if e, ok := used[s]; ok && e > i {
			return e, true
		}
	}
	return 0, false
}

// overlapsReportedDate reports whether data[start:end] overlaps a date
// already in used.
func overlapsReportedDate(used map[int]int, start, end int) bool {
	for s := max(0, start-maxExpiryLen+1); s < end; s++ {
		if e, ok := used[s]; ok && e > start {
			return true
		}
	}
	return false
}

// expiryKeywords are the context keywords used to identify card expiry mentions.
// Longer keywords are listed first so that "expiration" matches before "exp".
// Common mixed-case variants are included to reduce false negatives from
// case variations in real-world documents.
var expiryKeywords = newKeywordSet([][]byte{
	[]byte("expiration date"),
	[]byte("Expiration Date"),
	[]byte("Expiration date"),
	[]byte("EXPIRATION DATE"),
	[]byte("expiration"),
	[]byte("Expiration"),
	[]byte("EXPIRATION"),
	[]byte("valid through"),
	[]byte("Valid Through"),
	[]byte("Valid through"),
	[]byte("VALID THROUGH"),
	[]byte("valid thru"),
	[]byte("Valid Thru"),
	[]byte("Valid thru"),
	[]byte("VALID THRU"),
	[]byte("expires"),
	[]byte("Expires"),
	[]byte("EXPIRES"),
	[]byte("expiry"),
	[]byte("Expiry"),
	[]byte("EXPIRY"),
	[]byte("exp date"),
	[]byte("Exp Date"),
	[]byte("Exp date"),
	[]byte("EXP DATE"),
	[]byte("exp"),
	[]byte("Exp"),
	[]byte("EXP"),
	// Japanese: 有効期限
	{0xE6, 0x9C, 0x89, 0xE5, 0x8A, 0xB9, 0xE6, 0x9C, 0x9F, 0xE9, 0x99, 0x90},
})
