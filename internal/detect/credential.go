package detect

import (
	"bytes"
	"cmp"
	"slices"
	"strings"
)

const (
	authorizationKey      = "authorization"
	proxyAuthorizationKey = "proxyauthorization"
	credentialTokenKey    = "token"
	cookieKey             = "cookie"
	setCookieKey          = "setcookie"
)

// Credential implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindCredential.
type Credential struct {
	// MatchKey optionally replaces the default assignment-key policy.
	MatchKey func(string) bool
}

// Name returns the credential detection family.
func (*Credential) Name() DetectorName { return "credential" }

// Hints returns delimiters required by every supported credential form.
func (*Credential) Hints() [][]byte {
	return [][]byte{[]byte(":"), []byte("="), []byte("AKIA"), []byte("ASIA")}
}

// NormalizeCredentialKey removes ASCII case and key separators.
func NormalizeCredentialKey(key string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '_', '-', '.', ' ':
			return -1
		}
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, key)
}

// SensitiveCredentialKey implements the shared default key rule.
func SensitiveCredentialKey(key string) bool {
	switch NormalizeCredentialKey(key) {
	case "password", "passwd", "secret", credentialTokenKey, "apikey", authorizationKey, proxyAuthorizationKey, cookieKey, setCookieKey:
		return true
	}
	return false
}

func (d *Credential) secretKey(key []byte) bool {
	if d.MatchKey != nil && d.MatchKey(string(key)) {
		return true
	}
	// Normalize once into stack storage; every built-in key fits this bound.
	// Unknown labels are common in clean logs and must not allocate.
	const maxKeyBytes = 32
	var normalized [maxKeyBytes]byte
	n := 0
	for _, b := range key {
		if b == '_' || b == '-' || b == '.' || b == ' ' {
			continue
		}
		if n == len(normalized) {
			return false
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		normalized[n] = b
		n++
	}
	name := string(normalized[:n])
	if d.MatchKey == nil {
		switch name {
		case "password", "passwd", "secret", credentialTokenKey, "apikey", authorizationKey, proxyAuthorizationKey, cookieKey, setCookieKey:
			return true
		}
	}
	switch name {
	case "xamzsignature", "sig", "accountkey", "sharedaccesssignature", "awssecretaccesskey", "secretaccesskey", "privatekey", "clientsecret", "twilioauthtoken", "authtoken":
		return true
	}
	return false
}

// Scan returns only secret spans, never their surrounding configuration fields.
func (d *Credential) Scan(data []byte) []Finding {
	urls := urlPasswords(data)
	out := slices.Clone(urls)
	urlIndex := 0
	for i := 0; i < len(data); i++ {
		if data[i] != ':' && data[i] != '=' {
			continue
		}
		for urlIndex < len(urls) && urls[urlIndex].Start <= i {
			urlIndex++
		}
		// A userinfo username can itself be "token" or "password". Its
		// colon belongs to the URL, not an assignment extending past the host.
		if data[i] == ':' && urlIndex < len(urls) && urls[urlIndex].Start == i+1 {
			continue
		}
		key := d.credentialKey(data, i)
		if key == nil {
			continue
		}
		start, end := assignmentValue(data, i+1, NormalizeCredentialKey(string(key)))
		if end > start && string(data[start:end]) != "[REDACTED]" && (NormalizeCredentialKey(string(key)) != credentialTokenKey || !objectReference(data, start, end)) {
			out = append(out, credentialFinding(data, start, end))
			i = end - 1
		}
	}
	out = append(out, awsSecretPair(data)...)
	// Context and assignment recognizers may identify the same credential.
	slices.SortFunc(out, func(a, b Finding) int {
		if n := cmp.Compare(a.Start, b.Start); n != 0 {
			return n
		}
		return cmp.Compare(a.End, b.End)
	})
	return slices.CompactFunc(out, func(a, b Finding) bool { return a.Start == b.Start && a.End == b.End })
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

func assignmentValue(data []byte, start int, key string) (valueStart, valueEnd int) {
	for start < len(data) && (data[start] == ' ' || data[start] == '\t') {
		start++
	}
	if start == len(data) {
		return start, start
	}
	if data[start] == '"' || data[start] == '\'' {
		quote := data[start]
		start++
		end := start
		for end < len(data) {
			if data[end] == '\\' && end+1 < len(data) {
				end += 2
				continue
			}
			if data[end] == quote {
				break
			}
			end++
		}
		return authorizationValueStart(data, start, end, key), end
	}
	start = authorizationValueStart(data, start, len(data), key)
	const marker = "[REDACTED]"
	if bytes.HasPrefix(data[start:], []byte(marker)) {
		end := start + len(marker)
		if end == len(data) || strings.ContainsRune(" \t\r\n\"'},;)&]>#", rune(data[end])) {
			return start, end
		}
	}
	end := start
	for end < len(data) {
		c := data[end]
		if strings.ContainsRune("\r\n\"'},)]>", rune(c)) {
			break
		}
		if key != cookieKey && key != setCookieKey && (c == ' ' || c == '\t' || c == ';' || c == '&' || c == '#') {
			break
		}
		end++
	}
	return start, end
}

func credentialFinding(data []byte, start, end int) Finding {
	//nolint:mnd // Context identifies a credential; the score is a heuristic, not probability.
	return Finding{DetectorName: "credential", Start: start, End: end, Confidence: 0.95, RawValue: string(data[start:end])}
}

//nolint:dupl // Keep the pre-optimization parser as an independent differential oracle.
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
		segment := data[start:end]
		if scheme := bytes.Index(segment, []byte("://")); scheme >= 0 {
			start += scheme + len("://")
			segment = data[start:end]
			if tail := bytes.IndexAny(segment, "/?#"); tail >= 0 {
				segment = segment[:tail]
			}
		} else if !bytes.Contains(segment, []byte("@tcp(")) && !bytes.Contains(segment, []byte("@unix(")) {
			start = end
			continue
		}
		at := bytes.LastIndexByte(segment, '@')
		if at >= 0 {
			colon := bytes.IndexByte(segment[:at], ':')
			if colon >= 0 && !bytes.ContainsAny(segment[:colon], "/?#@") {
				secret := start + colon + 1
				stop := start + at
				if secret < stop && string(data[secret:stop]) != "[REDACTED]" {
					out = append(out, credentialFinding(data, secret, stop))
				}
			}
		}
		start = end
	}
	return out
}

func urlDelimiter(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '"', '\'', '<', '>':
		return true
	}
	return false
}

// awsSecretPair recognizes a 40-byte base64 secret within 128 bytes of an AWS
// access key ID. It does not infer ownership or validate credentials remotely.
func awsSecretPair(data []byte) []Finding {
	const awsContextBytes = 128
	var out []Finding
	for _, id := range NewAWSKey().Scan(data) {
		left, right := max(0, id.Start-awsContextBytes), min(len(data), id.End+awsContextBytes)
		for i := left; i < right; {
			if !awsSecretByte(data[i]) {
				i++
				continue
			}
			end := i + 1
			for end < right && awsSecretByte(data[end]) {
				end++
			}
			if end-i == 40 && (i == 0 || !awsSecretByte(data[i-1])) && (end == len(data) || !awsSecretByte(data[end])) {
				out = append(out, credentialFinding(data, i, end))
			}
			i = end
		}
	}
	return out
}
func awsSecretByte(b byte) bool { return isBase62(b) || b == '+' || b == '/' }

func authorizationValueStart(data []byte, start, end int, key string) int {
	if key == authorizationKey || key == proxyAuthorizationKey {
		for _, scheme := range []string{"Bearer ", "Basic "} {
			if end-start >= len(scheme) && strings.EqualFold(string(data[start:start+len(scheme)]), scheme) {
				start += len(scheme)
				for start < end && data[start] == ' ' {
					start++
				}
				return start
			}
		}
	}
	return start
}
