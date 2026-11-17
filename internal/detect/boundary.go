package detect

import "github.com/nao1215/embargo/internal/ascii"

// encodedSeparatorBefore recognizes percent-encoded log/query separators before
// a candidate without decoding its value or changing byte offsets. Encoded word
// characters, malformed escapes, and non-ASCII bytes are deliberately excluded.
func encodedSeparatorBefore(data []byte, start int) bool {
	if start < 3 || data[start-3] != '%' {
		return false
	}
	hi, ok := ascii.DecodeHex(data[start-2])
	if !ok {
		return false
	}
	lo, ok := ascii.DecodeHex(data[start-1])
	if !ok {
		return false
	}
	switch hi*16 + lo {
	case ' ', '\t', '\n', '\r', '"', '\'', '(', ')', '[', ']', '{', '}', ':', ',', ';', '=', '&', '?':
		return true
	default:
		return false
	}
}

// isWordBoundary reports whether the keyword match at data[pos:end] sits at
// word boundaries. A boundary violation occurs when the keyword edge byte is
// ASCII alphanumeric and the adjacent data byte is also ASCII alphanumeric,
// indicating the keyword is part of a longer word.
func isWordBoundary(data []byte, pos, end int, kw []byte) bool {
	// Check leading boundary.
	if pos > 0 && ascii.IsAlphaNum(kw[0]) && ascii.IsAlphaNum(data[pos-1]) && !encodedSeparatorBefore(data, pos) {
		return false
	}
	// Check trailing boundary.
	if end < len(data) && ascii.IsAlphaNum(kw[len(kw)-1]) && ascii.IsAlphaNum(data[end]) {
		return false
	}
	return true
}

// isIdentifierByte includes ASCII letters, digits and underscore. Numeric and
// identifier detectors use it to reject matches inside names; hyphens delimit them.
func isIdentifierByte(b byte) bool {
	return ascii.IsAlphaNum(b) || b == '_'
}

// isTokenByte reports whether b is a character that can appear inside a
// developer token body: an ASCII letter, digit, '_' or '-'. It is used for word
// boundary checks so a token embedded in a longer identifier is not matched.
func isTokenByte(b byte) bool {
	return ascii.IsAlphaNum(b) || b == '_' || b == '-'
}
