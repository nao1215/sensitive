package embargo

import "github.com/nao1215/embargo/internal/detect"

// WithSensitiveKeys replaces the default sensitive key set. No keys disables it.
// Defaults are password, passwd, secret, token, api_key, authorization, cookie
// and set-cookie. To extend them, include those names alongside your own keys.
// Matching ignores ASCII case and the separators underscore, hyphen, dot and
// space, so apiKey and API-KEY match api_key. Names are copied at construction.
// A match masks the entire value in slog attributes/groups and encoded JSON
// objects, including the zap, zerolog and logrus adapters. KindCredential also
// uses this policy for text assignments; its URL and provider-field rules remain
// independent. Use MaskJSON to check the complete structured key policy.
// An empty or separator-only name panics with a fixed message.
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

func normalizeKey(key string) string { return detect.NormalizeCredentialKey(key) }

func (s *Scanner) sensitiveKey(key string) bool {
	if s.sensitiveKeys != nil {
		key = normalizeKey(key)
		_, ok := s.sensitiveKeys[key]
		return ok
	}
	return detect.SensitiveCredentialKey(key)
}
