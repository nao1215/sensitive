package detect

import (
	"bytes"

	"github.com/nao1215/embargo/internal/ascii"
)

// curlUserPasswords finds the password in curl -u or --user arguments written
// as user:password, including quoted words and backslash-continued command
// lines. The username stays visible, as in URL userinfo; when the password is
// empty, as with an API key passed as the username, the username is reported.
// Other commands are ignored because their -u option has unrelated meanings,
// such as docker run -u uid:gid.
func curlUserPasswords(data []byte) []Finding {
	var out []Finding
	for i := 0; i+len("curl") <= len(data); i++ {
		next := bytes.Index(data[i:], []byte("curl"))
		if next < 0 {
			break
		}
		i += next
		if (i > 0 && isIdentifierByte(data[i-1])) || (i+len("curl") < len(data) && isIdentifierByte(data[i+len("curl")])) {
			continue
		}
		end := shellCommandEnd(data, i)
		out = appendCurlCommandPasswords(out, data, i+len("curl"), end)
		i = end
	}
	return out
}

// appendCurlCommandPasswords adds the user arguments of one curl command.
func appendCurlCommandPasswords(out []Finding, data []byte, start, end int) []Finding {
	for at := start; at < end; at++ {
		argument, ok := curlUserArgument(data, at, end)
		if !ok {
			continue
		}
		argEnd := shellWordEnd(data, argument, end)
		if secretStart, secretEnd, found := userinfoSecret(data, argument, argEnd); found {
			out = append(out, credentialFinding(secretStart, secretEnd))
		}
		at = argEnd
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

// flagValues finds the value of a long option whose name is a sensitive key
// when the value is a separate word: --password hunter2 or --db-password 'x'.
// The --password=x form is an assignment. A following option (a word that
// starts with -) and the words true and false are not values.
func (d *Credential) flagValues(data []byte) []Finding {
	var out []Finding
	for i := 0; i < len(data); {
		next := bytes.Index(data[i:], []byte("--"))
		if next < 0 {
			break
		}
		at := i + next
		i = at + len("--")
		if at > 0 && !isShellSpace(data[at-1]) {
			continue
		}
		if start, stop, end, ok := d.flagValue(data, i); ok {
			out = append(out, credentialFinding(start, stop))
			i = end
		}
	}
	return out
}

// flagValue returns the unquoted value word after the option name that starts
// at name, and where the word ends.
func (d *Credential) flagValue(data []byte, name int) (start, stop, end int, ok bool) {
	nameEnd := name
	for nameEnd < len(data) && (isIdentifierByte(data[nameEnd]) || data[nameEnd] == '-') {
		nameEnd++
	}
	if nameEnd == name || nameEnd >= len(data) || (data[nameEnd] != ' ' && data[nameEnd] != '\t') || !d.secretKey(data[name:nameEnd]) {
		return 0, 0, 0, false
	}
	line := shellCommandEnd(data, nameEnd)
	valueStart := skipShellSpace(data, nameEnd, line)
	end = shellWordEnd(data, valueStart, line)
	start, stop = trimShellQuotes(data, valueStart, end)
	return start, stop, end, start < stop && data[start] != '-' && !labelIs(data[start:stop], "true", "false")
}

// commandPasswords finds passwords passed to commands whose short -p option
// takes one: mysql and mariadb clients (mysqldump, mysqladmin and others)
// attach it as -phunter2, and sshpass takes it as the next word. The command
// name must begin a word on the same line, because -p means a port, a path or
// a parent directory elsewhere; mysql's -P port is upper-case.
func commandPasswords(data []byte) []Finding {
	// Every recognized password follows -p; most log lines have none.
	if !bytes.Contains(data, []byte("-p")) {
		return nil
	}
	var out []Finding
	for _, command := range []string{"mysql", "mariadb", "sshpass"} {
		for i := 0; i < len(data); {
			next := bytes.Index(data[i:], []byte(command))
			if next < 0 {
				break
			}
			i += next
			attached, ok := passwordCommand(data, i)
			if !ok {
				i += len(command)
				continue
			}
			end := shellCommandEnd(data, i)
			out = appendPasswordOptions(out, data, i, end, attached)
			i = end
		}
	}
	return out
}

// appendPasswordOptions adds the -p values of one command line.
func appendPasswordOptions(out []Finding, data []byte, start, end int, attached bool) []Finding {
	for at := start; at+len("-p") < end; at++ {
		if data[at] != '-' || data[at+1] != 'p' || (at > 0 && !isShellSpace(data[at-1])) {
			continue
		}
		valueStart := at + len("-p")
		// mysql -p alone prompts, so a separate word is a database name.
		if isShellSpace(data[valueStart]) == attached {
			continue
		}
		valueStart = skipShellSpace(data, valueStart, end)
		valueEnd := shellWordEnd(data, valueStart, end)
		if begin, stop := trimShellQuotes(data, valueStart, valueEnd); begin < stop {
			out = append(out, credentialFinding(begin, stop))
		}
		at = valueEnd
	}
	return out
}

// passwordCommand reports whether a mysql, mariadb or sshpass command word
// starts at i, and whether its -p option takes an attached value.
func passwordCommand(data []byte, i int) (attached, ok bool) {
	if i > 0 && (isIdentifierByte(data[i-1]) || data[i-1] == '-') {
		return false, false
	}
	end := i
	for end < len(data) && (ascii.IsLower(data[end]) || data[end] == '-') {
		end++
	}
	if end < len(data) && !isShellSpace(data[end]) {
		return false, false
	}
	word := data[i:end]
	switch {
	case bytes.HasPrefix(word, []byte("mysql")), bytes.HasPrefix(word, []byte("mariadb")):
		return true, true
	case string(word) == "sshpass":
		return false, true
	}
	return false, false
}
