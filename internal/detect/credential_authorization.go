package detect

import (
	"bytes"
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

// Apostrophes and backticks can belong to an RFC auth-scheme rather than
// enclose a value. A quote inside that token or at the next list scheme must
// not terminate the credentials that follow it.
func authorizationSchemeQuote(data []byte, start, end int, key string) bool {
	value := authorizationValueStart(data, start, len(data), key)
	if value == start {
		// Let the decoded view own a scheme separated by a serialized tab.
		return (key == authorizationKey || key == proxyAuthorizationKey) && hasASCIIPrefix(data, authSchemeEnd(data, start, len(data)), `\t`)
	}
	if end == len(data) || end < value {
		return true
	}
	before := bytes.TrimRight(data[start:end], " \t")
	// The non-whitespace scheme starts before value, so trimming cannot empty it.
	return before[len(before)-1] == ',' && authorizationValueStart(data, end, len(data), key) > end
}

// Authorization carries token68 or auth-param lists. Commas and quoted params
// belong to the same value; an outer quote or container still bounds the field.
func authorizationValueEnd(data []byte, start int) int {
	for end := start; end < len(data); end++ {
		// A reserved marker is one value inside a partially masked auth list;
		// its closing bracket must not hide credentials in later elements.
		if hasASCIIPrefix(data, end, credentialMarker) {
			end += len(credentialMarker) - 1
			continue
		}
		next, stop := authorizationValueByte(data, start, end)
		if stop {
			return next
		}
		end = next
	}
	return len(data)
}

// authorizationValueByte classifies the byte at end of an Authorization value.
// It returns the value end and true when the byte stops the value, otherwise
// the last consumed offset and false.
func authorizationValueByte(data []byte, start, end int) (int, bool) {
	c := data[end]
	switch {
	case serializedAuthorizationEscape(data, end):
		return start, true // Decoded params own their quotes.
	case c == '\r' || c == '\n':
		return end, true
	case c == ',':
		return authorizationValueComma(data, start, end)
	case c == '"' || c == '\'':
		if end == start || data[end-1] != '=' {
			return end, true
		}
		return credentialQuoteEnd(data, end+1, c), false
	case (c == '}' || c == ']' || c == ')' || c == '>') && !credentialAttachedTail(data, end):
		return end, true
	}
	return end, false
}

// serializedAuthorizationEscape reports a serialized backslash, quote or tab
// escape at end, which makes the decoded view own the whole value.
func serializedAuthorizationEscape(data []byte, end int) bool {
	return data[end] == '\\' && end+1 < len(data) && (data[end+1] == '\\' || data[end+1] == '"' || data[end+1] == 't')
}

// authorizationValueComma decides whether a comma starts another list
// credential, which the value then skips to, or hands the value to the decoded view.
func authorizationValueComma(data []byte, start, end int) (int, bool) {
	value := authorizationListValue(data, end+1)
	if value == 0 {
		return end, false
	}
	if value < 0 {
		return start, true // The decoded view owns this scheme separator.
	}
	return value - 1, false
}

// Return the next list credential offset, zero for an auth-param, or -1 when
// a serialized separator requires the decoded view to own the entire value.
func authorizationListValue(data []byte, next int) int {
	for next < len(data) && (data[next] == ' ' || data[next] == '\t') {
		next++
	}
	if hasASCIIPrefix(data, authSchemeEnd(data, next, len(data)), `\t`) {
		return -1
	}
	if value := authorizationValueStart(data, next, len(data), authorizationKey); value > next {
		return value
	}
	return 0
}

func authorizationValueStart(data []byte, start, end int, key string) int {
	if key != authorizationKey && key != proxyAuthorizationKey {
		return start
	}
	at := authSchemeEnd(data, start, end)
	if at == start || at == end || data[at] != ' ' && data[at] != '\t' {
		return start
	}
	for at < end && (data[at] == ' ' || data[at] == '\t') {
		at++
	}
	return at
}

func authSchemeEnd(data []byte, start, end int) int {
	for start < end && authSchemeByte(data[start]) {
		start++
	}
	return start
}

// RFC 9110 auth-scheme uses the HTTP token alphabet.
func authSchemeByte(b byte) bool {
	return ascii.IsAlphaNum(b) || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}

// Quoted header values retain their scheme even without an assignment label.
func quotedAuthorization(data []byte) []Finding {
	var out []Finding
	for i := nextQuote(data, 0); i >= 0; i = nextQuote(data, i+1) {
		// Without a key, arbitrary quoted prose is not an authorization value.
		tail := data[i+1:]
		if (len(tail) < len("Bearer ") || !strings.EqualFold(string(tail[:len("Bearer ")]), "Bearer ")) && (len(tail) < len("Basic ") || !strings.EqualFold(string(tail[:len("Basic ")]), "Basic ")) {
			continue
		}
		start := authorizationValueStart(data, i+1, len(data), authorizationKey)
		end := credentialContainerEnd(data, start, data[i])
		if end > start && string(data[start:end]) != credentialMarker {
			out = append(out, credentialFinding(start, end))
		}
		i = end
	}
	return out
}
