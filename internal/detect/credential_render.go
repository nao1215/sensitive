package detect

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// Serialized collections of reserved markers are already safe. Every other
// byte, including a marker with an attached suffix, still requires masking.
func redactedCredentialValue(data []byte) bool {
	marker := false
	for at := 0; at < len(data); {
		switch {
		case hasASCIIPrefix(data, at, credentialMarker):
			marker = true
			at += len(credentialMarker)
		case strings.ContainsRune(" \t\r\n\"'`[],", rune(data[at])):
			at++
		default:
			return false
		}
	}
	return marker
}

// assignmentValue owns boundaries for credential-key values in text and Go fmt output.
func assignmentValue(data []byte, start int, key string, formatted bool) (valueStart, valueEnd int) {
	fieldStart := start
	if start < len(data) && data[start] == '=' {
		start++
	} // Go's := assignment.
	for start < len(data) && (data[start] == ' ' || data[start] == '\t') {
		start++
	}
	if start == len(data) {
		return start, start
	}
	if end := credentialBlockEnd(data, fieldStart, start); end > start {
		return start, end
	}
	markerPrefix := bytes.HasPrefix(data[start:], []byte(credentialMarker))
	if markerPrefix && !credentialAttachedTail(data, start+len(credentialMarker)) {
		return start, start + len(credentialMarker)
	}
	if !markerPrefix {
		if begin, end, ok := credentialEnclosedValue(data, start, key); ok {
			return begin, end
		}
	}

	return credentialUnenclosedValue(data, start, key, formatted, markerPrefix)
}

func credentialEnclosedValue(data []byte, start int, key string) (begin, end int, ok bool) {
	if content, closeByte := credentialTypedValue(data, start); content > start {
		return content, credentialContainerEnd(data, content, closeByte), true
	}
	if hasASCIIPrefix(data, start, "map[") {
		begin = start + len("map[")
		return begin, credentialContainerEnd(data, begin, ']'), true
	}
	if data[start] == '[' {
		end = credentialContainerEnd(data, start+1, ']')
		if end == len(data) || !credentialAttachedTail(data, end+1) {
			return start + 1, end, true
		}
	}
	if data[start] == '"' || data[start] == '\'' || data[start] == '`' {
		end = credentialQuoteEnd(data, start+1, data[start])
		if authorizationSchemeQuote(data, start, end, key) {
			return start, start, false
		}
		return authorizationValueStart(data, start+1, end, key), end, true
	}
	return start, start, false
}

func credentialScalarEnd(data []byte, start, end int, key string, formatted bool) int {
	for end < len(data) {
		c := data[end]
		if c == '\r' || c == '\n' || c == '"' || c == '\'' {
			break
		}
		if strings.ContainsRune("},)]>", rune(c)) && end > start && !credentialAttachedTail(data, end) {
			break
		}
		if key != cookieKey && key != setCookieKey {
			if c == ';' || c == '&' || c == '#' {
				break
			}
			if (c == ' ' || c == '\t') && (!formatted || nextFmtField(data, end)) {
				break
			}
		}
		end++
	}
	return end
}

// A closing delimiter followed by a contiguous value is not a complete value.
func credentialAttachedTail(data []byte, at int) bool {
	for at < len(data) && (data[at] == ']' || data[at] == ')') {
		at++
	}
	return at < len(data) && (isAlphaNum(data[at]) || data[at] == '[')
}

// Go fmt emits a type before composite literals and named conversions. The
// type is left intact; the entire enclosed value, including byte lists, is masked.
func credentialTypedValue(data []byte, start int) (begin int, closeByte byte) {
	for at := start; at < len(data); at++ {
		c := data[at]
		if c == '{' && hasASCIIPrefix(data, at, "{}") {
			at++
			continue
		} // interface {} type.
		if c == '{' {
			return credentialStructValue(data, at), '}'
		}
		if c == '(' {
			return at + 1, ')'
		}
		if c < utf8.RuneSelf && !isAlphaNum(c) && !strings.ContainsRune("[]._*", rune(c)) && (c != ' ' || !credentialTypeSpace(data, at)) {
			break
		}
	}
	return start, 0
}

func credentialTypeSpace(data []byte, at int) bool {
	for _, word := range []string{"interface", "struct"} {
		if at >= len(word) && hasASCIIPrefix(data, at-len(word), word) {
			return true
		}
	}
	return false
}

// Anonymous struct types have their own braces before the actual value. Keep
// the type declaration intact and scan the following literal as one value.
func credentialStructValue(data []byte, opener int) int {
	const anonymous = "struct "
	if opener >= len(anonymous) && hasASCIIPrefix(data, opener-len(anonymous), anonymous) {
		end := credentialContainerEnd(data, opener+1, '}')
		if end+1 < len(data) && data[end+1] == '{' {
			return end + len("}{")
		}
	}
	return opener + 1
}

func fmtCredentialContext(data []byte, formatted bool) bool {
	for _, c := range data {
		switch c {
		case '{', '[':
			formatted = true
		case '\n', '=', '"', '\'':
			formatted = false
		}
	}
	return formatted
}

func nextFmtField(data []byte, start int) bool {
	for start < len(data) && (data[start] == ' ' || data[start] == '\t') {
		start++
	}
	for start < len(data) && (isAlphaNum(data[start]) || strings.ContainsRune("_.-", rune(data[start]))) {
		start++
	}
	return start < len(data) && data[start] == ':'
}

// A fmt slice is one credential value, including every element and scheme.
func credentialContainerEnd(data []byte, start int, closeByte byte) int {
	if closeByte == '"' || closeByte == '\'' || closeByte == '`' {
		return credentialQuoteEnd(data, start, closeByte)
	}
	depth := 0
	for i := start; i < len(data); i++ {
		c := data[i]
		switch c {
		case '"', '\'', '`':
			i = credentialQuoteEnd(data, i+1, c)
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			if depth == 0 && c == closeByte {
				return i
			}
			if depth > 0 {
				depth--
			}
		}
	}
	return len(data)
}

// credentialQuoteEnd shares escaped and raw-quote handling across fmt values.
func credentialQuoteEnd(data []byte, start int, quote byte) int {
	for i := start; i < len(data); i++ {
		if data[i] == '\\' && quote != '`' && i+1 < len(data) {
			i++
			continue
		}
		if data[i] == quote {
			return i
		}
	}
	return len(data)
}

// Check the original unquoted object prefix before a Go composite parser can
// mistake Java's Class{identity rendering for a field-bearing struct.
func unquotedObjectValue(data []byte, start int) bool {
	for start < len(data) && (data[start] == ' ' || data[start] == '\t') {
		start++
	}
	end := start
	for end < len(data) && !strings.ContainsRune(" \t\r\n},", rune(data[end])) {
		end++
	}
	return objectReference(data, start, end)
}

// Block scalar contents belong to the credential until indentation returns to
// the key's level. Other YAML syntax is not inferred from free text.
func credentialBlockEnd(data []byte, fieldStart, start int) int {
	if data[start] != '|' && data[start] != '>' {
		return start
	}
	line := bytes.LastIndexByte(data[:fieldStart], '\n') + 1
	indent := 0
	for line+indent < len(data) && data[line+indent] == ' ' {
		indent++
	}
	end := start + 1
	for end < len(data) && strings.ContainsRune("+-123456789 \r", rune(data[end])) {
		end++
	}
	if end == len(data) || data[end] != '\n' {
		return start
	}
	end++
	for end < len(data) {
		next := end
		for next < len(data) && data[next] == ' ' {
			next++
		}
		if next < len(data) && data[next] != '\n' && data[next] != '\r' && next-end <= indent {
			break
		}
		stop := bytes.IndexByte(data[next:], '\n')
		if stop < 0 {
			return len(data)
		}
		end = next + stop + 1
	}
	return end
}

// credentialUnenclosedValue handles scalar tails after container and quote ownership is known.
func credentialUnenclosedValue(data []byte, start int, key string, formatted, markerPrefix bool) (valueStart, valueEnd int) {
	start = authorizationValueStart(data, start, len(data), key)
	if bytes.HasPrefix(data[start:], []byte(credentialMarker)) && !credentialAttachedTail(data, start+len(credentialMarker)) && (start+len(credentialMarker) == len(data) || data[start+len(credentialMarker)] != ',') {
		return start, start + len(credentialMarker)
	}
	if key == authorizationKey || key == proxyAuthorizationKey {
		return start, authorizationValueEnd(data, start)
	}
	end := start
	if markerPrefix {
		end += len(credentialMarker)
	}
	return start, credentialScalarEnd(data, start, end, key, formatted)
}

func (d *Credential) credentialKey(data []byte, end int) []byte {
	key := assignmentKey(data, end)
	if d.secretKey(key) {
		return key
	}
	for end > 0 && (data[end-1] == ' ' || data[end-1] == '\t') {
		end--
	}
	start := end - len(key)
	if start > 0 && data[start-1] == ' ' {
		prev := start - 1
		for prev > 0 && isAlpha(data[prev-1]) {
			prev--
		}
		key = data[prev:end]
	}
	if d.secretKey(key) {
		return key
	}
	return nil
}

func assignmentKey(data []byte, end int) []byte {
	for end > 0 && (data[end-1] == ' ' || data[end-1] == '\t') {
		end--
	}
	if end > 0 && (data[end-1] == '"' || data[end-1] == '\'') {
		quote := data[end-1]
		end--
		start := end
		for start > 0 && data[start-1] != quote && data[start-1] != '\n' {
			start--
		}
		return data[start:end]
	}
	start := end
	for start > 0 && (isAlphaNum(data[start-1]) || strings.ContainsRune("_-.", rune(data[start-1]))) {
		start--
	}
	return data[start:end]
}
