package ascii

import "slices"

// HasLetter reports whether data contains at least one ASCII letter (a-z, A-Z).
func HasLetter(data []byte) bool {
	return slices.ContainsFunc(data, IsAlpha)
}

// IsDigit reports whether b is an ASCII digit (0-9).
func IsDigit(b byte) bool { return b >= '0' && b <= '9' }

// IsUpper reports whether b is an ASCII uppercase letter (A-Z).
func IsUpper(b byte) bool { return b >= 'A' && b <= 'Z' }

// IsLower reports whether b is an ASCII lowercase letter (a-z).
func IsLower(b byte) bool { return b >= 'a' && b <= 'z' }

// IsAlpha reports whether b is an ASCII letter.
func IsAlpha(b byte) bool { return IsLower(b) || IsUpper(b) }

// IsAlphaNum reports whether b is an ASCII letter or digit.
func IsAlphaNum(b byte) bool { return IsAlpha(b) || IsDigit(b) }

// IsAlphaNumRune reports whether r is an ASCII letter or digit.
func IsAlphaNumRune(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
}

// ToLowerRune converts an ASCII uppercase letter to lowercase; other runes are unchanged.
func ToLowerRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// IsHexDigit reports whether b is an ASCII hexadecimal digit in either case.
func IsHexDigit(b byte) bool {
	_, ok := DecodeHex(b)
	return ok
}

// LowerCopy returns a new byte slice with all ASCII uppercase letters
// converted to lowercase. Non-ASCII bytes are copied unchanged.
func LowerCopy(data []byte) []byte {
	return AppendLower(make([]byte, 0, len(data)), data)
}

// AppendLower appends data to dst with ASCII uppercase letters lowered, so a
// caller can lower a short window into a stack buffer.
func AppendLower(dst, data []byte) []byte {
	for _, b := range data {
		dst = append(dst, ToLower(b))
	}
	return dst
}

// ContainsFold reports whether data contains lower, ignoring ASCII case in
// data. lower must already be lowercase; non-ASCII bytes match only themselves.
func ContainsFold(data, lower []byte) bool {
	for i := 0; i+len(lower) <= len(data); i++ {
		if hasPrefixFold(data[i:], lower) {
			return true
		}
	}
	return false
}

// hasPrefixFold reports whether data starts with lower, ignoring ASCII case in data.
func hasPrefixFold(data, lower []byte) bool {
	for j, b := range lower {
		if ToLower(data[j]) != b {
			return false
		}
	}
	return true
}

// ToLower converts an ASCII uppercase letter to lowercase.
// Non-uppercase bytes are returned unchanged.
func ToLower(b byte) byte {
	if IsUpper(b) {
		return b + ('a' - 'A')
	}
	return b
}

// ToUpper converts an ASCII lowercase letter to uppercase.
// Non-lowercase bytes are returned unchanged.
func ToUpper(b byte) byte {
	if IsLower(b) {
		return b - ('a' - 'A')
	}
	return b
}

// LowerString returns s with ASCII uppercase letters converted to lowercase.
// Other bytes, including invalid UTF-8, are kept unchanged.
func LowerString(s string) string {
	return string(LowerCopy([]byte(s)))
}

// DecodeHex returns the value of one ASCII hexadecimal digit and whether it is valid.
func DecodeHex(b byte) (byte, bool) {
	const firstLetterValue = 10
	if b >= '0' && b <= '9' {
		return b - '0', true
	}
	if b >= 'a' && b <= 'f' {
		return b - 'a' + firstLetterValue, true
	}
	if b >= 'A' && b <= 'F' {
		return b - 'A' + firstLetterValue, true
	}
	return 0, false
}
