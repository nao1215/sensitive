package detect

import "strings"

// quotedArgumentPairs finds a quoted value passed right after a quoted
// credential key in an argument or initializer list, as in Java's
// System.setProperty("db.password", "x"), put("api_key", "x") or
// Map.of("password", "x"). The key opens the list or follows a comma.
func (d *Credential) quotedArgumentPairs(data []byte) []Finding {
	var out []Finding
	for i := 0; i < len(data); i++ {
		if data[i] != '"' && data[i] != '\'' {
			continue
		}
		keyEnd := credentialQuoteEnd(data, i+1, data[i])
		if keyEnd == len(data) {
			break
		}
		start, end, ok := d.argumentValue(data, i, keyEnd)
		if ok {
			out = append(out, credentialFinding(start, end))
			keyEnd = end
		}
		i = keyEnd
	}
	return out
}

// argumentValue returns the quoted value after the key quoted from open to
// keyEnd when the key names a credential and opens an argument list or follows
// a comma, and a comma separates it from the value.
func (d *Credential) argumentValue(data []byte, open, keyEnd int) (start, end int, ok bool) {
	if !argumentListItem(data, open) || !d.secretKey(data[open+1:keyEnd]) {
		return 0, 0, false
	}
	at := skipBlanks(data, keyEnd+1)
	if at == len(data) || data[at] != ',' {
		return 0, 0, false
	}
	at = skipBlanks(data, at+1)
	if at == len(data) || (data[at] != '"' && data[at] != '\'') {
		return 0, 0, false
	}
	end = credentialQuoteEnd(data, at+1, data[at])
	start = authorizationValueStart(data, at+1, end, NormalizeCredentialKey(string(data[open+1:keyEnd])))
	return start, end, end > start && !redactedCredentialValue(data[start:end])
}

// argumentListItem reports whether the quote at open starts an argument or
// initializer list item: the byte before it, past blanks, is (, { or a comma.
func argumentListItem(data []byte, open int) bool {
	before := open
	for before > 0 && (data[before-1] == ' ' || data[before-1] == '\t') {
		before--
	}
	return before > 0 && strings.ContainsRune("({,", rune(data[before-1]))
}
