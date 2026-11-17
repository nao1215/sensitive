package detect

import (
	"bytes"
)

func urlPasswords(data []byte) []Finding {
	// Both URI userinfo and the Go MySQL DSN require an at-sign.
	if !bytes.ContainsRune(data, '@') {
		return nil
	}
	var out []Finding
	for start := 0; start < len(data); {
		if urlDelimiter(data[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(data) && !urlDelimiter(data[end]) {
			end++
		}
		if f, ok := urlSegmentPassword(data, start, end); ok {
			out = append(out, f)
		}
		start = end
	}
	return out
}

// urlSegmentPassword returns the password between the userinfo colon and the
// last at-sign of a URL or DSN segment, skipping an already masked marker.
func urlSegmentPassword(data []byte, start, end int) (Finding, bool) {
	start, segment, ok := urlAuthority(data, start, end)
	if !ok {
		return Finding{}, false
	}
	at := bytes.LastIndexByte(segment, '@')
	if at < 0 {
		return Finding{}, false
	}
	colon := bytes.IndexByte(segment[:at], ':')
	if colon < 0 || bytes.ContainsAny(segment[:colon], "/?#@") {
		return Finding{}, false
	}
	secret := start + colon + 1
	stop := start + at
	if secret < stop && string(data[secret:stop]) != credentialMarker {
		return credentialFinding(secret, stop), true
	}
	return Finding{}, false
}

// urlAuthority narrows a delimited segment to the URI authority after its
// scheme, or keeps a whole Go MySQL DSN; other segments carry no userinfo.
func urlAuthority(data []byte, start, end int) (authorityStart int, segment []byte, ok bool) {
	segment = data[start:end]
	if scheme := bytes.Index(segment, []byte("://")); scheme >= 0 {
		start += scheme + len("://")
		segment = data[start:end]
		if tail := bytes.IndexAny(segment, "/?#"); tail >= 0 {
			segment = segment[:tail]
		}
		return start, segment, true
	}
	if !bytes.Contains(segment, []byte("@tcp(")) && !bytes.Contains(segment, []byte("@unix(")) {
		return start, segment, false
	}
	return start, segment, true
}

func urlDelimiter(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '"', '\'', '<', '>':
		return true
	}
	return false
}

// url.URL's field rendering has no :// or @. Both neighboring field names are
// required, preventing an ordinary User label from becoming a credential key.
func formattedURLPasswords(data []byte) []Finding {
	var out []Finding
	for at := 0; at < len(data); {
		found := bytes.Index(data[at:], []byte(" User:"))
		if found < 0 {
			break
		}
		start := at + found + len(" User:")
		end := start
		for end < len(data) && data[end] != ' ' && data[end] != '\n' {
			end++
		}
		if hasASCIIPrefix(data, end, " Host:") {
			if colon := bytes.IndexByte(data[start:end], ':'); colon >= 0 && start+colon+1 < end {
				out = append(out, credentialFinding(start+colon+1, end))
			}
		}
		at = end
	}
	return out
}
