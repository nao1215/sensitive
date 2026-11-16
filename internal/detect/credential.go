package detect

import (
	"bytes"
	"cmp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	authorizationKey      = "authorization"
	proxyAuthorizationKey = "proxyauthorization"
	credentialTokenKey    = "token"
	cookieKey             = "cookie"
	setCookieKey          = "setcookie"
	credentialMarker      = "[REDACTED]"
	credentialSecretKey   = "secret"
)

// Credential implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindCredential.
type Credential struct {
	// MatchKey optionally replaces the default assignment-key policy.
	MatchKey func(string) bool
}

// Name returns the credential detection family.
func (*Credential) Name() DetectorName { return DetectorName(KindCredential) }

// Hints returns delimiters required by every supported credential form.
func (*Credential) Hints() [][]byte {
	return [][]byte{[]byte(":"), []byte("="), []byte("AKIA"), []byte("ASIA"), []byte("Bearer "), []byte("Basic ")}
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
	return credentialSuffix(key) || sensitiveNormalizedKey(NormalizeCredentialKey(key))
}

func sensitiveNormalizedKey(key string) bool {
	switch key {
	case "password", "passwd", credentialSecretKey, credentialTokenKey, "apikey", authorizationKey, proxyAuthorizationKey, cookieKey, setCookieKey, "accesstoken", "refreshtoken", "idtoken", "xapikey", "dbpassword", "privatetoken", "clientsecret", "authtoken", "pgpassword":
		return true
	}
	return false
}

func (d *Credential) secretKey(key []byte) bool {
	if d.MatchKey == nil && credentialSuffix(string(key)) {
		return true
	}
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
	if d.MatchKey == nil && sensitiveNormalizedKey(name) {
		return true
	}
	switch name {
	case "xamzsignature", "sig", "accountkey", "sharedaccesssignature", "awssecretaccesskey", "secretaccesskey", "privatekey", "clientsecret", "twilioauthtoken", "authtoken":
		return true
	}
	return false
}

// Scan returns only secret spans, never their surrounding configuration fields.
func (d *Credential) Scan(data []byte) []Finding {
	out := d.scanPlain(data)
	input := data
	var positions []int
	const layers = 4
	for range layers {
		decoded, mapping := credentialQuotes(input)
		if mapping == nil {
			break
		}
		if positions != nil {
			for i, at := range mapping {
				mapping[i] = positions[at]
			}
		}
		next := d.scanPlain(decoded)
		previous := 0
		added := make([]Finding, 0, len(next))
		for _, f := range next {
			f.Start, f.End = mapping[f.Start], mapping[f.End]
			// A valid less-escaped value owns its quotes. Decoding its interior again
			// must not reinterpret an escaped quote as the end of that value.
			for previous < len(out) && out[previous].End <= f.Start {
				previous++
			}
			if previous < len(out) && out[previous].Start < f.End && (f.Start >= out[previous].Start || f.End < out[previous].End) {
				continue
			}
			f.RawValue = string(data[f.Start:f.End])
			added = append(added, f)
		}
		out = append(out, added...)
		slices.SortFunc(out, func(a, b Finding) int { return cmp.Compare(a.Start, b.Start) })
		input, positions = decoded, mapping
	}
	return out
}

// Decode one quote/backslash escape layer. Positions
// map each decoded boundary to the original bytes, including escaped secrets.
func credentialQuotes(data []byte) (decoded []byte, positions []int) {
	if !bytes.Contains(data, []byte(`\"`)) && !bytes.Contains(data, []byte(`\\`)) && !bytes.Contains(data, []byte(`\x22`)) && !bytes.Contains(data, []byte(`\u0022`)) && !bytes.Contains(data, []byte(`\t`)) {
		return data, nil
	}
	decoded = make([]byte, 0, len(data))
	positions = make([]int, 0, len(data)+1)
	for i := 0; i < len(data); i++ {
		positions = append(positions, i)
		if hasASCIIPrefix(data, i, `\t`) {
			decoded = append(decoded, '\t')
			i++
			continue
		}
		if hasASCIIPrefix(data, i, `\x22`) {
			decoded = append(decoded, '"')
			i += 3
			continue
		}
		if hasASCIIPrefix(data, i, `\u0022`) {
			decoded = append(decoded, '"')
			i += 5
			continue
		}
		if data[i] == '\\' && i+1 < len(data) && (data[i+1] == '"' || data[i+1] == '\\') {
			i++
		}
		decoded = append(decoded, data[i])
	}
	positions = append(positions, len(data))
	return decoded, positions
}

func (d *Credential) scanPlain(data []byte) []Finding {
	urls := urlPasswords(data)
	out := slices.Clone(urls)
	urlIndex := 0
	contextAt, formatted := 0, false
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
		name := NormalizeCredentialKey(string(key))
		if name == credentialTokenKey && unquotedObjectValue(data, i+1) {
			continue
		}
		// Visit each context byte once, including values skipped by this loop.
		// Long keys and preceding fields must not lose their enclosing fmt shape.
		formatted = fmtCredentialContext(data[contextAt:i], formatted)
		contextAt = i
		start, end := assignmentValue(data, i+1, name, data[i] == ':' && formatted)
		if end > start && !redactedCredentialValue(data[start:end]) && (name != credentialTokenKey || !objectReference(data, start, end)) {
			out = append(out, credentialFinding(data, start, end))
			i = end - 1
		}
	}
	out = append(out, formattedURLPasswords(data)...)
	out = append(out, awsSecretPair(data)...)
	out = append(out, quotedAuthorization(data)...)
	// Context and assignment recognizers may identify the same credential.
	slices.SortFunc(out, func(a, b Finding) int {
		if n := cmp.Compare(a.Start, b.Start); n != 0 {
			return n
		}
		return cmp.Compare(a.End, b.End)
	})
	return slices.CompactFunc(out, func(a, b Finding) bool { return a.Start == b.Start && a.End == b.End })
}

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

// Authorization carries token68 or auth-param lists. Commas and quoted params
// belong to the same value; an outer quote or container still bounds the field.
func authorizationValueEnd(data []byte, start int) int {
	for end := start; end < len(data); end++ {
		c := data[end]
		if c == '\\' && end+1 < len(data) && (data[end+1] == '\\' || data[end+1] == '"' || data[end+1] == 't') {
			return start
		} // Decoded params own their quotes.
		if c == '\r' || c == '\n' {
			return end
		}
		if c == ',' {
			next := end + 1
			for next < len(data) && (data[next] == ' ' || data[next] == '\t') {
				next++
			}
			if value := authorizationValueStart(data, next, len(data), authorizationKey); value > next {
				end = value - 1
				continue
			}
		}
		if c == '"' || c == '\'' {
			if end == start || data[end-1] != '=' {
				return end
			}
			end = credentialQuoteEnd(data, end+1, c)
			continue
		}
		if (c == '}' || c == ']' || c == ')' || c == '>') && !credentialAttachedTail(data, end) {
			return end
		}
	}
	return len(data)
}

func credentialFinding(data []byte, start, end int) Finding {
	//nolint:mnd // Context identifies a credential; the score is a heuristic, not probability.
	return Finding{DetectorName: DetectorName(KindCredential), Start: start, End: end, Confidence: 0.95, RawValue: string(data[start:end])}
}

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
				if secret < stop && string(data[secret:stop]) != credentialMarker {
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
	if key != authorizationKey && key != proxyAuthorizationKey {
		return start
	}
	at := start
	for at < end && authSchemeByte(data[at]) {
		at++
	}
	if at == start || at == end || data[at] != ' ' && data[at] != '\t' {
		return start
	}
	for at < end && (data[at] == ' ' || data[at] == '\t') {
		at++
	}
	return at
}

// RFC 9110 auth-scheme uses the HTTP token alphabet.
func authSchemeByte(b byte) bool {
	return isAlphaNum(b) || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
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

// Quoted header values retain their scheme even without an assignment label.
func quotedAuthorization(data []byte) []Finding {
	var out []Finding
	for i := 0; i < len(data); i++ {
		if data[i] != '"' && data[i] != '\'' {
			continue
		}
		// Without a key, arbitrary quoted prose is not an authorization value.
		tail := data[i+1:]
		if (len(tail) < len("Bearer ") || !strings.EqualFold(string(tail[:len("Bearer ")]), "Bearer ")) && (len(tail) < len("Basic ") || !strings.EqualFold(string(tail[:len("Basic ")]), "Basic ")) {
			continue
		}
		start := authorizationValueStart(data, i+1, len(data), authorizationKey)
		if start == i+1 {
			continue
		}
		end := credentialContainerEnd(data, start, data[i])
		if end > start && string(data[start:end]) != credentialMarker {
			out = append(out, credentialFinding(data, start, end))
		}
		i = end
	}
	return out
}

// Credential suffixes require a separator or camel-case segment boundary, so
// token_count, primary_key and ordinary words do not become credentials.
func credentialSuffix(key string) bool {
	if key == "" {
		return false
	}
	var candidates []string
	switch key[len(key)-1] | 0x20 {
	case 'd':
		candidates = []string{"password", "passwd"}
	case 't':
		candidates = []string{credentialSecretKey}
	case 'n':
		candidates = []string{credentialTokenKey}
	case 'l':
		candidates = []string{string(KindCredential)}
	case 'h':
		candidates = []string{"auth"}
	case 'y':
		candidates = []string{"key"}
	default:
		return false
	}
	for _, word := range candidates {
		start := len(key) - len(word)
		if start < 0 || !strings.EqualFold(key[start:], word) || credentialSegmentStart(key) != start {
			continue
		}
		if word != "key" {
			return true
		}
		if start == 0 {
			return false
		}
		prefix := strings.TrimRight(key[:start], "_.- ")
		previous := prefix[credentialSegmentStart(prefix):]
		for _, credential := range []string{"api", credentialSecretKey, "private", "access", "account"} {
			if strings.EqualFold(previous, credential) {
				return true
			}
		}
	}
	return false
}

func credentialSegmentStart(key string) int {
	start := 0
	for i := range len(key) {
		if strings.ContainsRune("_.- ", rune(key[i])) {
			start = i + 1
			continue
		}
		if i > 0 && key[i] >= 'A' && key[i] <= 'Z' && (key[i-1] >= 'a' && key[i-1] <= 'z' || i+1 < len(key) && key[i+1] >= 'a' && key[i+1] <= 'z') {
			start = i
		}
	}
	return start
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
				out = append(out, credentialFinding(data, start+colon+1, end))
			}
		}
		at = end
	}
	return out
}

// ScanViews adds normalized assignments while raw URL delimiters retain ownership
// of percent-escaped userinfo. Mapping always refers to original input bytes.
func (d *Credential) ScanViews(raw, normalized []byte, positions []int) []Finding {
	out := d.Scan(raw)
	if positions == nil {
		return out
	}
	previous, rawCount := 0, len(out)
	for _, f := range d.Scan(normalized) {
		f.Start, f.End = positions[f.Start], positions[f.End]
		for previous < rawCount && out[previous].End <= f.Start {
			previous++
		}
		if previous < rawCount && out[previous].Start < f.End && (f.Start >= out[previous].Start || f.End < out[previous].End) {
			continue
		}
		f.RawValue = string(raw[f.Start:f.End])
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Finding) int { return cmp.Compare(a.Start, b.Start) })
	return out
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
