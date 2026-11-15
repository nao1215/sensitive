package embargo

import "strings"

// WithSensitiveKeys replaces the default sensitive key set. No keys disables it.
// Defaults are password, passwd, secret, token, api_key, authorization, cookie
// and set-cookie. To extend them, include those names alongside your own keys.
// Matching ignores ASCII case and the separators underscore, hyphen, dot and
// space, so apiKey and API-KEY match api_key. Names are copied at construction.
// A match masks the entire value in slog attributes/groups and encoded JSON
// objects, including the zap, zerolog and logrus adapters. Text Scan is unchanged;
// use MaskJSON in an embargotest expectation to check structured key policy.
func WithSensitiveKeys(keys ...string) ScannerOption {
	selected := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		normalized := normalizeKey(key)
		if normalized == "" {
			panic("embargo: empty sensitive key")
		}
		selected[normalized] = struct{}{}
	}
	return scannerOption(func(s *Scanner) { s.sensitiveKeys = selected })
}

func normalizeKey(key string) string {
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

func (s *Scanner) sensitiveKey(key string) bool {
	key = normalizeKey(key)
	if s.sensitiveKeys != nil {
		_, ok := s.sensitiveKeys[key]
		return ok
	}
	switch key {
	case "password", "passwd", "secret", "token", "apikey", "authorization", "cookie", "setcookie":
		return true
	}
	return false
}
