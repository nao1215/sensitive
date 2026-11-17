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

// isAlpha reports whether b is an ASCII letter.
func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isAlphaNum reports whether b is an ASCII alphanumeric character.
func isAlphaNum(b byte) bool {
	return isAlpha(b) || isDigit(b)
}

// isWordBoundary reports whether the keyword match at data[pos:end] sits at
// word boundaries. A boundary violation occurs when the keyword edge byte is
// ASCII alphanumeric and the adjacent data byte is also ASCII alphanumeric,
// indicating the keyword is part of a longer word.
func isWordBoundary(data []byte, pos, end int, kw []byte) bool {
	// Check leading boundary.
	if pos > 0 && isAlphaNum(kw[0]) && isAlphaNum(data[pos-1]) && !encodedSeparatorBefore(data, pos) {
		return false
	}
	// Check trailing boundary.
	if end < len(data) && isAlphaNum(kw[len(kw)-1]) && isAlphaNum(data[end]) {
		return false
	}
	return true
}

// isIdentifierByte includes ASCII letters, digits and underscore. Numeric and
// identifier detectors use it to reject matches inside names; hyphens delimit them.
func isIdentifierByte(b byte) bool {
	return isAlphaNum(b) || b == '_'
}

// isTokenByte reports whether b is a character that can appear inside a
// developer token body: an ASCII letter, digit, '_' or '-'. It is used for word
// boundary checks so a token embedded in a longer identifier is not matched.
func isTokenByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_' || b == '-':
		return true
	default:
		return false
	}
}

// isHexDigit shares the hexadecimal alphabet with percent decoding.
func isHexDigit(b byte) bool {
	_, ok := ascii.DecodeHex(b)
	return ok
}
