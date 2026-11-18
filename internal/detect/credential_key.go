package detect

import (
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

const (
	authorizationKey      = "authorization"
	proxyAuthorizationKey = "proxyauthorization"
	credentialTokenKey    = "token"
	cookieKey             = "cookie"
	setCookieKey          = "setcookie"
	credentialMarker      = "[REDACTED]"
	credentialSecretKey   = "secret"
	shortPassKey          = "pass"
	shortPasswordKey      = "pwd"
)

// NormalizeCredentialKey removes ASCII case and key separators.
func NormalizeCredentialKey(key string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '_', '-', '.', ' ':
			return -1
		}
		return ascii.ToLowerRune(r)
	}, key)
}

// SensitiveCredentialKey implements the shared default key rule.
// Structured keys also accept the bare abbreviations pass and pwd, which the
// text grammar leaves alone because pass=12 reports test results and PWD=/srv
// is the working directory in environment dumps.
func SensitiveCredentialKey(key string) bool {
	normalized := NormalizeCredentialKey(key)
	return credentialSuffix(key) || sensitiveNormalizedKey(normalized) || normalized == shortPassKey || normalized == shortPasswordKey
}

func sensitiveNormalizedKey(key string) bool {
	switch key {
	case "password", "passwd", credentialSecretKey, credentialTokenKey, "apikey", authorizationKey, proxyAuthorizationKey, cookieKey, setCookieKey, "accesstoken", "refreshtoken", "idtoken", "xapikey", "dbpassword", "privatetoken", "clientsecret", "authtoken", "pgpassword",
		"otp", "pin", "passcode", "passphrase", "session", "sessionid", "sessiontoken", "jsessionid", "phpsessid":
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
		normalized[n] = ascii.ToLower(b)
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

// unnumberedKey removes a trailing number and its separator, so numbered
// keys such as api_token_2 or password1 keep their meaning.
func unnumberedKey(key string) (base string, numbered bool) {
	end := len(key)
	for end > 0 && ascii.IsDigit(key[end-1]) {
		end--
	}
	if end == len(key) {
		return key, false
	}
	for end > 0 && strings.IndexByte("_.- ", key[end-1]) >= 0 {
		end--
	}
	return key[:end], true
}

// Credential suffixes require a separator or camel-case segment boundary, so
// token_count, primary_key and ordinary words do not become credentials.
func credentialSuffix(key string) bool {
	if key == "" {
		return false
	}
	if base, numbered := unnumberedKey(key); numbered {
		return base != "" && credentialSuffix(base)
	}
	var candidates []string
	switch key[len(key)-1] | 0x20 {
	case 'd':
		candidates = []string{"password", "passwd", shortPasswordKey}
	case 'e':
		candidates = []string{"passcode", "passphrase"}
	case 'p':
		candidates = []string{"otp"}
	case 't':
		candidates = []string{credentialSecretKey}
	case 'n':
		candidates = []string{credentialTokenKey}
	case 'l':
		candidates = []string{string(NameCredential)}
	case 's':
		candidates = []string{"credentials", "creds", shortPassKey}
	case 'h':
		candidates = []string{"auth"}
	case 'y':
		candidates = []string{"key", "apikey", "accesskey", "secretkey", "privatekey"}
	default:
		return false
	}
	return credentialSuffixMatch(key, candidates)
}

// credentialSuffixMatch reports whether key ends with one of the candidate
// words as its own segment; a bare "key" suffix also needs a credential qualifier.
func credentialSuffixMatch(key string, candidates []string) bool {
	for _, word := range candidates {
		start := len(key) - len(word)
		if start < 0 || !strings.EqualFold(key[start:], word) || credentialSegmentStart(key) != start {
			continue
		}
		if word != "key" {
			// Bare pass and pwd are not credentials in text; db_pass is.
			return (word != shortPassKey && word != shortPasswordKey) || strings.TrimRight(key[:start], "_.- ") != ""
		}
		if start == 0 {
			return false
		}
		if qualifiedKeySuffix(key[:start]) {
			return true
		}
	}
	return false
}

// qualifiedKeySuffix reports whether the segment before a "key" suffix names
// a credential, so api_key matches while primary_key does not.
func qualifiedKeySuffix(head string) bool {
	prefix := strings.TrimRight(head, "_.- ")
	previous := prefix[credentialSegmentStart(prefix):]
	for _, credential := range []string{"api", credentialSecretKey, "private", "access", "account"} {
		if strings.EqualFold(previous, credential) {
			return true
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
		if i > 0 && ascii.IsUpper(key[i]) && (ascii.IsLower(key[i-1]) || i+1 < len(key) && ascii.IsLower(key[i+1])) {
			start = i
		}
	}
	return start
}
