package detector

import "bytes"

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

// findKeywordPositions returns all positions where any of the given keywords
// appear in data at word boundaries. The search is performed using
// bytes.Index for efficiency. Keywords containing ASCII letters are matched
// case-insensitively (ASCII-only), while non-ASCII keywords are matched
// byte-for-byte.
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
func findKeywordPositions(data []byte, keywords [][]byte) []keywordMatch {
	var matches []keywordMatch

	needFold := false
	for _, kw := range keywords {
		if hasASCIILetter(kw) {
			needFold = true
			break
		}
	}

	var foldedData []byte
	if needFold {
		foldedData = asciiLowerCopy(data)
	}

	for _, kw := range keywords {
		if len(kw) == 0 {
			continue
		}

		haystack := data
		needle := kw
		if needFold && hasASCIILetter(kw) {
			haystack = foldedData
			needle = asciiLowerCopy(kw)
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
			if !isWordBoundary(data, pos, end, kw) {
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

// isWordBoundary reports whether the keyword match at data[pos:end] sits at
// word boundaries. A boundary violation occurs when the keyword edge byte is
// ASCII alphanumeric and the adjacent data byte is also ASCII alphanumeric,
// indicating the keyword is part of a longer word.
func isWordBoundary(data []byte, pos, end int, kw []byte) bool {
	// Check leading boundary.
	if pos > 0 && isASCIIAlphaNum(kw[0]) && isASCIIAlphaNum(data[pos-1]) {
		return false
	}
	// Check trailing boundary.
	if end < len(data) && isASCIIAlphaNum(kw[len(kw)-1]) && isASCIIAlphaNum(data[end]) {
		return false
	}
	return true
}

// isASCIIAlphaNum reports whether b is an ASCII letter or digit.
func isASCIIAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func hasASCIILetter(data []byte) bool {
	for _, b := range data {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			return true
		}
	}
	return false
}

func asciiLowerCopy(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = toLowerASCII(b)
	}
	return out
}

func toLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// extractDigitsNear finds all digit sequences within the given byte radius
// of a position. Only sequences with digit count between minDigits and maxDigits
// (inclusive) are returned. The position is typically the end of a keyword match.
//
// The radius extends both before and after the keyword position:
//   - Before: data[max(0, pos-radius) : pos]
//   - After:  data[pos : min(len(data), pos+radius)]
func extractDigitsNear(data []byte, pos, radius, minDigits, maxDigits int) []digitSequence {
	searchStart := pos - radius
	if searchStart < 0 {
		searchStart = 0
	}
	searchEnd := pos + radius
	if searchEnd > len(data) {
		searchEnd = len(data)
	}

	var results []digitSequence

	i := searchStart
	for i < searchEnd {
		if !isDigit(data[i]) {
			i++
			continue
		}

		// Found start of digit sequence.
		seqStart := i
		for i < searchEnd && isDigit(data[i]) {
			i++
		}
		seqEnd := i

		// Skip sequences truncated at the search boundary. If a digit
		// sequence touches the boundary edge and continues beyond it,
		// the captured portion is a fragment of a longer number — not
		// a standalone sequence. Including it would cause false positives
		// (e.g., the tail of a 20-digit number appearing as an 8-digit
		// bank account number).
		if seqStart == searchStart && searchStart > 0 && isDigit(data[searchStart-1]) {
			continue
		}
		if seqEnd == searchEnd && searchEnd < len(data) && isDigit(data[searchEnd]) {
			continue
		}

		digitCount := seqEnd - seqStart
		if digitCount >= minDigits && digitCount <= maxDigits {
			results = append(results, digitSequence{start: seqStart, end: seqEnd})
		}
	}

	return results
}

// extractAlphaNumNear finds all alphanumeric sequences within the given byte
// radius of a position. Only sequences with character count between minLen and
// maxLen (inclusive) are returned.
//
// Sequences that are truncated at the search boundary are excluded.
// If a sequence touches the boundary edge and continues beyond it,
// the captured portion is a fragment of a longer token — not a standalone
// identifier. Including it would cause false positives (e.g., the tail of
// a 30-character string appearing as a 15-character merchant ID).
//
//nolint:unparam // minLen is kept as a parameter for API consistency with extractDigitsNear.
func extractAlphaNumNear(data []byte, pos, radius, minLen, maxLen int) []digitSequence {
	searchStart := pos - radius
	if searchStart < 0 {
		searchStart = 0
	}
	searchEnd := pos + radius
	if searchEnd > len(data) {
		searchEnd = len(data)
	}

	var results []digitSequence

	i := searchStart
	for i < searchEnd {
		if !isAlphaNum(data[i]) {
			i++
			continue
		}

		seqStart := i
		for i < searchEnd && isAlphaNum(data[i]) {
			i++
		}
		seqEnd := i

		// Skip sequences truncated at the search boundary.
		if seqStart == searchStart && searchStart > 0 && isAlphaNum(data[searchStart-1]) {
			continue
		}
		if seqEnd == searchEnd && searchEnd < len(data) && isAlphaNum(data[searchEnd]) {
			continue
		}

		seqLen := seqEnd - seqStart
		if seqLen >= minLen && seqLen <= maxLen {
			results = append(results, digitSequence{start: seqStart, end: seqEnd})
		}
	}

	return results
}
