package detect

// curlUserPasswords finds the password in curl -u or --user arguments written
// as user:password, including quoted words and backslash-continued command
// lines. The username stays visible, as in URL userinfo; when the password is
// empty, as with an API key passed as the username, the username is reported.
// Other commands are ignored because their -u option has unrelated meanings,
// such as docker run -u uid:gid.
func curlUserPasswords(data []byte) []Finding {
	var out []Finding
	for i := 0; i+len("curl") <= len(data); i++ {
		if !hasASCIIPrefix(data, i, "curl") || (i > 0 && isIdentifierByte(data[i-1])) || (i+len("curl") < len(data) && isIdentifierByte(data[i+len("curl")])) {
			continue
		}
		end := shellCommandEnd(data, i)
		for at := i + len("curl"); at < end; at++ {
			argument, ok := curlUserArgument(data, at, end)
			if !ok {
				continue
			}
			argEnd := shellWordEnd(data, argument, end)
			if start, stop, found := userinfoSecret(data, argument, argEnd); found {
				out = append(out, credentialFinding(start, stop))
			}
			at = argEnd
		}
		i = end
	}
	return out
}

// shellCommandEnd returns the end of the line, following backslash
// continuations.
func shellCommandEnd(data []byte, start int) int {
	for at := start; at < len(data); at++ {
		if data[at] == '\n' && (at == 0 || data[at-1] != '\\') {
			return at
		}
	}
	return len(data)
}

// curlUserArgument reports where the argument of -u or --user starts when the
// option begins at a word boundary at position at.
func curlUserArgument(data []byte, at, end int) (argument int, ok bool) {
	if at > 0 && !isShellSpace(data[at-1]) {
		return 0, false
	}
	next := at
	switch {
	case hasASCIIPrefix(data, at, "--user="):
		next += len("--user=")
		return next, next < end
	case hasASCIIPrefix(data, at, "--user"):
		next += len("--user")
	case hasASCIIPrefix(data, at, "-u"):
		next += len("-u")
	default:
		return 0, false
	}
	if next >= end || !isShellSpace(data[next]) {
		return 0, false
	}
	next = skipShellSpace(data, next, end)
	return next, next < end
}

// skipShellSpace skips blanks and backslash-newline continuations.
func skipShellSpace(data []byte, at, end int) int {
	for at < end && (isShellSpace(data[at]) || (data[at] == '\\' && at+1 < end && data[at+1] == '\n')) {
		at++
	}
	return at
}

// shellWordEnd returns the end of one shell word made of quoted and unquoted parts.
func shellWordEnd(data []byte, start, end int) int {
	at := start
	for at < end && !isShellSpace(data[at]) {
		if data[at] == '"' || data[at] == '\'' {
			quote := data[at]
			at++
			for at < end && data[at] != quote {
				if quote == '"' && data[at] == '\\' {
					at++
				}
				at++
			}
		}
		at++
	}
	return min(at, end)
}

// userinfoSecret splits a user:password word at its first colon and returns
// the password span without its enclosing quotes.
func userinfoSecret(data []byte, start, end int) (secretStart, secretEnd int, ok bool) {
	colon := -1
	for at := start; at < end && colon < 0; at++ {
		if data[at] == ':' {
			colon = at
		}
	}
	if colon < 0 {
		return 0, 0, false
	}
	secretStart, secretEnd = trimShellQuotes(data, colon+1, end)
	if secretStart == secretEnd {
		secretStart, secretEnd = trimShellQuotes(data, start, colon)
	}
	return secretStart, secretEnd, secretStart < secretEnd
}

func trimShellQuotes(data []byte, start, end int) (trimmedStart, trimmedEnd int) {
	for start < end && (data[start] == '"' || data[start] == '\'') {
		start++
	}
	for end > start && (data[end-1] == '"' || data[end-1] == '\'') {
		end--
	}
	return start, end
}

func isShellSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }
