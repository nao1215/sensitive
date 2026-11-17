package embargo

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/nao1215/embargo/internal/detect"
	"github.com/nao1215/embargo/internal/saferecord"
)

// WithSensitiveKeys replaces the default sensitive key set. No keys disables it.
// Defaults are password, passwd, secret, token, api_key, authorization,
// proxy-authorization, cookie, set-cookie, access_token, refresh_token, id_token,
// x-api-key, DB_PASSWORD, Private-Token, client_secret, auth_token and PGPASSWORD.
// Keys also match when the last separator/camel-case segment is password, passwd,
// secret, token, credential or auth; key requires an api, secret, private, access
// or account segment before it. Thus SECRET_KEY, POSTGRES_PASSWORD, GITHUB_TOKEN,
// X-Auth-Token and spring.datasource.password match, but primary_key, sort_key
// and token_count do not. A custom set replaces this suffix policy as well.
// Include the application keys you need alongside your own keys.
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

// Field keys repeat across events, and their masked spelling and sensitivity
// depend only on the scanner's immutable built-in policy. Only keys without
// findings are cached, so it holds no detected value. The cache is bounded
// in entries and key length; once full it stops admitting keys, so unique keys
// pay one map lookup instead of evicting the keys that repeat.
const (
	maxCachedKeys     = 1024
	maxCachedKeyBytes = 64
)

type keyResult struct {
	masked    string
	sensitive bool
}

type keyCache struct {
	entries sync.Map
	size    atomic.Int64
}

func (c *keyCache) load(key string) (keyResult, bool) {
	value, ok := c.entries.Load(key)
	if !ok {
		return keyResult{}, false
	}
	result, ok := value.(keyResult)
	return result, ok
}

func (c *keyCache) store(key string, result keyResult) {
	if c.size.Add(1) > maxCachedKeys {
		c.size.Add(-1)
		return
	}
	if _, loaded := c.entries.LoadOrStore(key, result); loaded {
		c.size.Add(-1)
	}
}

// cacheableKey excludes numeric-looking keys, which maskScalar also checks as
// exact integers with a second budget charge, and keys too long to keep.
func (s *Scanner) cacheableKey(key string) bool {
	return s.keys != nil && key != "" && len(key) <= maxCachedKeyBytes && key[0] != '-' && (key[0] < '0' || key[0] > '9')
}

// maskKey is maskScalar(ctx, key, "") with its result cached per scanner. A hit
// performs the same cancellation and budget checks and charges as a scan.
func (s *eventScanner) maskKey(ctx context.Context, key string) (keyResult, error) {
	if !s.scanner.cacheableKey(key) {
		masked, err := s.maskScalar(ctx, key, "")
		return keyResult{masked: masked, sensitive: err == nil && s.scanner.sensitiveKey(key)}, err
	}
	if ctx.Err() != nil {
		return keyResult{}, saferecord.ErrCanceled
	}
	if len(key) > s.remaining {
		return keyResult{}, saferecord.ErrSizeLimit
	}
	if result, ok := s.scanner.keys.load(key); ok {
		s.remaining -= len(key)
		return result, nil
	}
	masked, err := s.maskScalar(ctx, key, "")
	if err != nil {
		return keyResult{}, err
	}
	result := keyResult{masked: masked, sensitive: s.scanner.sensitiveKey(key)}
	// Only clean keys are kept, so the cache never holds detected values.
	if masked == key {
		s.scanner.keys.store(key, result)
	}
	return result, nil
}

// cachedSensitiveKey answers sensitiveKey from the cache when maskKey has seen key.
func (s *Scanner) cachedSensitiveKey(key string) bool {
	if s.cacheableKey(key) {
		if result, ok := s.keys.load(key); ok {
			return result.sensitive
		}
	}
	return s.sensitiveKey(key)
}
