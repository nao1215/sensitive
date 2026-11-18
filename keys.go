package embargo

import (
	"context"
	"maps"
	"sync"
	"sync/atomic"

	"github.com/nao1215/embargo/internal/ascii"
	"github.com/nao1215/embargo/internal/detect"
	"github.com/nao1215/embargo/internal/saferecord"
)

// WithSensitiveKeys adds names to the sensitive key policy; repeated options add
// to each other and the defaults stay. Defaults are password, passwd, secret, token, api_key, authorization,
// proxy-authorization, cookie, set-cookie, access_token, refresh_token, id_token,
// x-api-key, DB_PASSWORD, Private-Token, client_secret, auth_token, PGPASSWORD,
// otp, pin, passcode, passphrase, session, session_id, session_token, JSESSIONID
// and PHPSESSID; structured keys also accept the bare pass and pwd, which text
// assignments leave alone because pass=12 and PWD=/srv are common public text.
// Keys also match when the last separator/camel-case segment is password, passwd,
// pwd, passcode, passphrase, otp, secret, token, credential or auth, or pass after
// another segment (DB_PASS); key requires an api, secret, private, access
// or account segment before it. Thus SECRET_KEY, POSTGRES_PASSWORD, GITHUB_TOKEN,
// X-Auth-Token and spring.datasource.password match, but primary_key, sort_key
// and token_count do not. WithoutDefaultSensitiveKeys drops the defaults and
// this suffix rule. Matching ignores ASCII case and the separators underscore, hyphen, dot and
// space, so apiKey and API-KEY match api_key. Names are copied at construction.
// A match masks the entire value in slog attributes/groups and encoded JSON
// objects, including the zap, zerolog and logrus adapters. An object that keeps
// a setting as separate members, such as {"name":"DB_PASSWORD","value":"x"} in
// Kubernetes env, ECS, SSM or CloudFormation, has its value string masked when
// the name, key, ParameterKey, ParameterName, OptionName or variable member is a
// sensitive key; the last segment of a parameter path such as /prod/db/password counts. KindCredential also
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
	return scannerOption(func(s *Scanner) {
		if s.sensitiveKeys == nil {
			s.sensitiveKeys = make(map[string]struct{}, len(selected))
		}
		maps.Copy(s.sensitiveKeys, selected)
	})
}

// WithoutDefaultSensitiveKeys drops the default names and the suffix rule, so
// only names added with WithSensitiveKeys mask whole values; with none, the key
// policy is off. Use it when a default name such as token holds public data, and
// add back the names that do hold secrets.
func WithoutDefaultSensitiveKeys() ScannerOption {
	return scannerOption(func(s *Scanner) { s.noDefaultKeys = true })
}

func normalizeKey(key string) string { return detect.NormalizeCredentialKey(key) }

func (s *Scanner) sensitiveKey(key string) bool {
	if _, ok := s.sensitiveKeys[normalizeKey(key)]; ok {
		return true
	}
	return !s.noDefaultKeys && detect.SensitiveCredentialKey(key)
}

// Field keys and log messages repeat across events, and their masked spelling and sensitivity
// depend only on the scanner's immutable built-in policy. Only keys without
// findings are cached, so it holds no detected value. The cache is bounded
// in entries and key length; once full it stops admitting keys, so unique keys
// pay one map lookup instead of evicting the keys that repeat.
const (
	maxCachedKeys     = 1024
	maxCachedKeyBytes = 64
)

type keyResult struct {
	key       string
	masked    string
	sensitive bool
}

// keyCache publishes an immutable map, so lookups take no lock and a lookup by
// bytes allocates nothing. New keys wait in a pending map under a mutex and are
// published together once the pending set is as large as the published one or
// a pending key is stored again, so keys seen once cost no copy and the copies
// over a scanner's life stay near twice the admitted keys. Until then a
// pending key is scanned again, which returns the same result.
type keyCache struct {
	entries atomic.Pointer[map[string]keyResult]
	pending map[string]keyResult
	mu      sync.Mutex
}

func (c *keyCache) published() map[string]keyResult {
	if entries := c.entries.Load(); entries != nil {
		return *entries
	}
	return nil
}

func (c *keyCache) load(key string) (keyResult, bool) {
	result, ok := c.published()[key]
	return result, ok
}

func (c *keyCache) loadBytes(key []byte) (keyResult, bool) {
	result, ok := c.published()[string(key)]
	return result, ok
}

func (c *keyCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.published()) + len(c.pending)
}

func (c *keyCache) store(key string, result keyResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current := c.published()
	if _, published := current[key]; published {
		return
	}
	// A pending key that is scanned again is hot: publish the batch now, so a
	// small, stable key set never waits for the doubling rule.
	_, repeated := c.pending[key]
	if !repeated {
		if len(current)+len(c.pending) >= maxCachedKeys {
			return
		}
		if c.pending == nil {
			c.pending = make(map[string]keyResult)
		}
		result.key = key
		c.pending[key] = result
		if len(c.pending) < len(current) {
			return
		}
	}
	next := make(map[string]keyResult, len(current)+len(c.pending))
	maps.Copy(next, current)
	maps.Copy(next, c.pending)
	c.entries.Store(&next)
	c.pending = nil
}

// cacheableKey excludes numeric-looking keys, which maskScalar also checks as
// exact integers with a second budget charge, and keys too long to keep.
func cacheableKey[T string | []byte](s *Scanner, key T) bool {
	return s.keys != nil && len(key) > 0 && len(key) <= maxCachedKeyBytes && key[0] != '-' && !ascii.IsDigit(key[0])
}

// cachedKey returns a cached result for key after the cancellation and budget
// checks and charge that scanning it would apply. A miss charges nothing.
func cachedKey[T string | []byte](ctx context.Context, s *eventScanner, key T) (keyResult, bool, error) {
	if !cacheableKey(s.scanner, key) {
		return keyResult{}, false, nil
	}
	if ctx.Err() != nil {
		return keyResult{}, false, saferecord.ErrCanceled
	}
	if len(key) > s.remaining {
		return keyResult{}, false, saferecord.ErrSizeLimit
	}
	var result keyResult
	var ok bool
	switch typed := any(key).(type) {
	case string:
		result, ok = s.scanner.keys.load(typed)
	case []byte:
		result, ok = s.scanner.keys.loadBytes(typed)
	}
	if ok {
		s.remaining -= len(key)
	}
	return result, ok, nil
}

// maskCached is maskScalar(ctx, key, "") with its result cached per scanner. A hit
// performs the same cancellation and budget checks and charges as a scan.
func (s *eventScanner) maskCached(ctx context.Context, key string) (keyResult, error) {
	if result, ok, err := cachedKey(ctx, s, key); ok || err != nil {
		return result, err
	}
	masked, err := s.maskScalar(ctx, key, "")
	if err != nil {
		return keyResult{}, err
	}
	result := keyResult{key: key, masked: masked, sensitive: s.scanner.sensitiveKey(key)}
	// Only clean keys are kept, so the cache never holds detected values.
	if masked == key && cacheableKey(s.scanner, key) {
		s.scanner.keys.store(key, result)
	}
	return result, nil
}

// cachedSensitiveKey answers sensitiveKey from the cache when maskCached has seen key.
func (s *Scanner) cachedSensitiveKey(key string) bool {
	if cacheableKey(s, key) {
		if result, ok := s.keys.load(key); ok {
			return result.sensitive
		}
	}
	return s.sensitiveKey(key)
}
