package detect

import "github.com/nao1215/embargo/internal/ascii"

// CardExpiry implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindCardExpiry.
type CardExpiry struct {
	expiryKeywords *keywordSet
}

// NewCardExpiry finds labeled expiration dates without requiring them to be in the future.
func NewCardExpiry() *CardExpiry {
	return &CardExpiry{expiryKeywords: expiryKeywords()}
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
	matches := d.expiryKeywords.findPositions(data)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding
	// used maps the start of each reported date to its end. One place in the
	// text is often matched by several keywords ("exp", "Exp" and "EXP" are
	// all compared case-insensitively), so the same range is searched more
	// than once. Only parsed date candidates need an overlap lookup; ordinary
	// bytes cannot overlap a reported date in a way that creates a finding.
	used := make(map[int]int)

	for _, m := range matches {
		// Search within a 50-byte radius before the keyword for date patterns.
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		beforeStart := max(m.start-50, 0)
		d.searchRange(data, beforeStart, m.start, used, &findings)

		// Search within a 50-byte radius after the keyword for date patterns.
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		afterEnd := min(m.end+50, len(data))
		d.searchRange(data, m.end, afterEnd, used, &findings)
	}

	return findings
}

// expiryCandidate holds a parsed expiry date pattern.
type expiryCandidate struct {
	dateEnd int
}

// parseExpiryCandidate checks whether data[i:] starts with a valid MM/YY or
// MM/YYYY pattern. Returns the parsed candidate and true, or false if invalid.
func parseExpiryCandidate(data []byte, i int) (expiryCandidate, bool) {
	if !ascii.IsDigit(data[i]) || !ascii.IsDigit(data[i+1]) {
		return expiryCandidate{}, false
	}
	sep := data[i+2]
	if sep != '/' && sep != '-' {
		return expiryCandidate{}, false
	}
	if i+5 > len(data) {
		return expiryCandidate{}, false
	}
	if !ascii.IsDigit(data[i+3]) || !ascii.IsDigit(data[i+4]) {
		return expiryCandidate{}, false
	}

	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	dateEnd := i + 5
	if i+7 <= len(data) && ascii.IsDigit(data[i+5]) && ascii.IsDigit(data[i+6]) {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		dateEnd = i + 7
	}

	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	month := int(data[i]-'0')*10 + int(data[i+1]-'0')
	if month < 1 || month > 12 {
		return expiryCandidate{}, false
	}

	return expiryCandidate{dateEnd: dateEnd}, true
}

// searchRange scans data[start:end] for card expiry date patterns (MM/YY,
// MM/YYYY, MM-YY, MM-YYYY) and appends any valid findings to results.
// The used map makes repeated keyword windows idempotent. Parse first and
// consult it only for valid candidates, avoiding per-byte overlap map probes.
// Month/year strings are copied only after a candidate survives deduplication.
func (d *CardExpiry) searchRange(data []byte, start, end int, used map[int]int, results *[]Finding) {
	for i := start; i < end-4; i++ {
		c, ok := parseExpiryCandidate(data, i)
		if !ok {
			continue
		}

		// Word boundary: no digit before or after.
		if i > 0 && ascii.IsDigit(data[i-1]) && !encodedSeparatorBefore(data, i) {
			continue
		}
		if c.dateEnd < len(data) && ascii.IsDigit(data[c.dateEnd]) {
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
			//nolint:mnd // The detector contract documents this heuristic score.
			Confidence: 0.85,
		})

		i = c.dateEnd - 1
	}
}

// maxExpiryLen is the length of the longest date searchRange reports (MM/YYYY).
const maxExpiryLen = 7

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
func expiryKeywords() *keywordSet {
	return newKeywordSet([][]byte{
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
}
