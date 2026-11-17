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
		candidates = []string{string(NameCredential)}
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
		if i > 0 && ascii.IsUpper(key[i]) && (ascii.IsLower(key[i-1]) || i+1 < len(key) && ascii.IsLower(key[i+1])) {
			start = i
		}
	}
	return start
}
