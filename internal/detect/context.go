package detect

import (
	"bytes"

	"github.com/nao1215/embargo/internal/ascii"
)

// keywordMatch represents a position where a keyword was found in the data.
type keywordMatch struct {
	// start is the byte offset where the keyword begins.
	start int
	// end is the byte offset where the keyword ends (exclusive).
	end int
}

// digitSequence represents a consecutive sequence of ASCII digits found in data.
type digitSequence struct {
	// start is the byte offset where the digit sequence begins.
	start int
	// end is the byte offset where the digit sequence ends (exclusive).
	end int
}

// keywordEntry holds the original keyword and its pre-computed lowercase form.
type keywordEntry struct {
	// original is the keyword as provided by the caller.
	original []byte
	// lowered is ascii.LowerCopy(original) when the keyword contains ASCII
	// letters; otherwise it is the same slice as original.
	lowered []byte
	// needFold is true when the keyword contains ASCII letters.
	needFold bool
}

// keywordSet holds pre-computed keyword data so that ascii.LowerCopy is not
// called on every Scan invocation. Construct one via newKeywordSet and reuse
// it across calls to findPositions.
type keywordSet struct {
	entries  []keywordEntry
	needFold bool // true if any entry requires case folding
}

// newKeywordSet pre-computes lowered forms for the given keywords.
func newKeywordSet(keywords [][]byte) *keywordSet {
	entries := make([]keywordEntry, 0, len(keywords))
	anyFold := false
	for _, kw := range keywords {
		if len(kw) == 0 {
			continue
		}
		e := keywordEntry{original: kw}
		if ascii.HasLetter(kw) {
			e.lowered = ascii.LowerCopy(kw)
			e.needFold = true
			anyFold = true
		} else {
			e.lowered = kw
		}
		entries = append(entries, e)
	}
	return &keywordSet{entries: entries, needFold: anyFold}
}

// findPositions returns all positions where any keyword in the set appears in
// data at word boundaries.
//
// Keywords containing ASCII letters are matched case-insensitively (ASCII-only),
// while non-ASCII keywords are matched byte-for-byte.
//
// A word boundary check prevents partial matches inside longer words.
// When the keyword edge character is ASCII alphanumeric, the adjacent
// character in the data must NOT also be ASCII alphanumeric. For example,
// keyword "exp" will match "exp: 12/25" but not "example". Keywords
// starting or ending with non-alphanumeric characters (e.g., "MID:")
// skip the boundary check on that side.
//
// Non-ASCII (multi-byte) boundary characters are always accepted, so
// Japanese keywords embedded in kanji text match without restriction.
func (ks *keywordSet) findPositions(data []byte) []keywordMatch {
	var matches []keywordMatch

	var foldedData []byte
	if ks.needFold {
		foldedData = ascii.LowerCopy(data)
	}

	for _, e := range ks.entries {
		haystack := data
		needle := e.original
		if e.needFold {
			haystack = foldedData
			needle = e.lowered
		}
		offset := 0
		for {
			idx := bytes.Index(haystack[offset:], needle)
			if idx < 0 {
				break
			}
			pos := offset + idx
			end := pos + len(needle)

			// Word boundary check: reject matches embedded inside
			// a larger alphanumeric token.
			if !isWordBoundary(data, pos, end, e.original) {
				offset = pos + 1
				continue
			}

			matches = append(matches, keywordMatch{
				start: pos,
				end:   end,
			})
			offset = end
		}
	}

	return matches
}

// findKeywordPositions is a convenience wrapper that creates a temporary
// keywordSet from keywords and searches data. For repeated calls with the
// same keywords, prefer newKeywordSet + findPositions to avoid per-call
// allocations.
func findKeywordPositions(data []byte, keywords [][]byte) []keywordMatch {
	return newKeywordSet(keywords).findPositions(data)
}

// extractDigitsNear finds all digit sequences within the given byte radius
// of a position. Only sequences with digit count between minDigits and maxDigits
// (inclusive) are returned. The position is typically the end of a keyword match.
//
// The radius extends both before and after the keyword position:
//   - Before: data[max(0, pos-radius) : pos]
//   - After:  data[pos : min(len(data), pos+radius)]
func extractDigitsNear(data []byte, pos, radius, minDigits, maxDigits int) []digitSequence {
	return extractNear(data, pos, radius, minDigits, maxDigits, isDigit)
}

// extractAlphaNumNear applies the same boundary rules to alphanumeric tokens.
func extractAlphaNumNear(data []byte, pos, radius, minLen, maxLen int) []digitSequence {
	return extractNear(data, pos, radius, minLen, maxLen, isAlphaNum)
}

func extractNear(data []byte, pos, radius, minLen, maxLen int, accept func(byte) bool) []digitSequence {
	searchStart := max(pos-radius, 0)
	searchEnd := min(pos+radius, len(data))

	var results []digitSequence

	i := searchStart
	for i < searchEnd {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if data[i] == '%' && i+3 <= searchEnd && encodedSeparatorBefore(data, i+3) {
			i += 3
			continue
		}
		if !accept(data[i]) {
			i++
			continue
		}

		// Found start of digit sequence.
		seqStart := i
		for i < searchEnd && accept(data[i]) {
			i++
		}
		seqEnd := i

		// Skip sequences truncated at the search boundary. If a digit
		// sequence touches the boundary edge and continues beyond it,
		// the captured portion is a fragment of a longer number — not
		// a standalone sequence. Including it would cause false positives
		// (e.g., the tail of a 20-digit number appearing as an 8-digit
		// bank account number).
		if seqStart == searchStart && searchStart > 0 && accept(data[searchStart-1]) && !encodedSeparatorBefore(data, searchStart) {
			continue
		}
		if seqEnd == searchEnd && searchEnd < len(data) && accept(data[searchEnd]) {
			continue
		}

		digitCount := seqEnd - seqStart
		if digitCount >= minLen && digitCount <= maxLen {
			results = append(results, digitSequence{start: seqStart, end: seqEnd})
		}
	}

	return results
}
