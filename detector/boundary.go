package detector

// encodedSeparatorBefore recognizes percent-encoded log/query separators before
// a candidate without decoding its value or changing byte offsets. Encoded word
// characters, malformed escapes, and non-ASCII bytes are deliberately excluded.
func encodedSeparatorBefore(data []byte, start int) bool {
	if start < 3 || data[start-3] != '%' {
		return false
	}
	hi, ok := boundaryHex(data[start-2])
	if !ok {
		return false
	}
	lo, ok := boundaryHex(data[start-1])
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

// boundaryHex decodes one hexadecimal digit without allocating.
func boundaryHex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}
