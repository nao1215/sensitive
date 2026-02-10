package ascii

// HasLetter reports whether data contains at least one ASCII letter (a-z, A-Z).
func HasLetter(data []byte) bool {
	for _, b := range data {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			return true
		}
	}
	return false
}

// LowerCopy returns a new byte slice with all ASCII uppercase letters
// converted to lowercase. Non-ASCII bytes are copied unchanged.
func LowerCopy(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ToLower(b)
	}
	return out
}

// ToLower converts an ASCII uppercase letter to lowercase.
// Non-uppercase bytes are returned unchanged.
func ToLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
