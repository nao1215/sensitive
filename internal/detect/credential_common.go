package detect

// Shared helpers for the developer-credential detectors (GitHub / Slack / Google
// API key / PEM private key). These credentials are identified by a fixed ASCII
// prefix followed by a bounded character set, so they use dedicated byte scanners
// (no regular expressions) in keeping with the library's performance-first rule.

// hasASCIIPrefix reports whether data[i:] begins with the ASCII string p, without
// allocating. It returns false when p would run past the end of data.
func hasASCIIPrefix(data []byte, i int, p string) bool {
	if i < 0 || i+len(p) > len(data) {
		return false
	}
	for k := range len(p) {
		if data[i+k] != p[k] {
			return false
		}
	}
	return true
}

// credBoundary reports whether data[start:end] is delimited by non-token bytes on
// both sides, so a credential is not matched as a substring of a longer word.
func credBoundary(data []byte, start, end int) bool {
	if !credStartBoundary(data, start) {
		return false
	}
	if end < len(data) && isTokenByte(data[end]) {
		return false
	}
	return true
}

// scanCharset advances from start while data[j] satisfies allow, returning the
// exclusive end index and how many bytes were consumed.
func scanCharset(data []byte, start int, allow func(byte) bool) (end, n int) {
	j := start
	for j < len(data) && allow(data[j]) {
		j++
	}
	return j, j - start
}

// credStartBoundary rejects impossible prefixes before traversing a token body.
func credStartBoundary(data []byte, start int) bool {
	return leadingBoundary(data, start, isTokenByte)
}

// allBytes reports whether every byte in data[start:end] satisfies allow.
func allBytes(data []byte, start, end int, allow func(byte) bool) bool {
	for k := start; k < end; k++ {
		if !allow(data[k]) {
			return false
		}
	}
	return true
}
