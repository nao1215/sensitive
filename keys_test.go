package embargo

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/saferecord"
)

// statusKey is a clean field name and tokenKey a credential one.
const (
	statusKey = "status"
	tokenKey  = "token"
)

func TestMaskKeyCacheHitMatchesScan(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	for _, key := range []string{statusKey, credentialFixtureKey, documentedEmail, "17", "-1", strings.Repeat("k", maxCachedKeyBytes+1)} {
		t.Run(key[:min(len(key), 20)], func(t *testing.T) {
			t.Parallel()
			want, wantErr := (&eventScanner{scanner: scanner, remaining: maxScanBytes}).maskScalar(context.Background(), key, "")
			for range 2 {
				scan := eventScanner{scanner: scanner, remaining: maxScanBytes}
				got, err := scan.maskCached(context.Background(), key)
				if got.masked != want || !errors.Is(err, wantErr) || got.sensitive != scanner.sensitiveKey(key) {
					t.Fatalf("maskCached(%q) = %+v, %v; want %q, %v", key, got, err, want, wantErr)
				}
				if scan.remaining != maxScanBytes-len(key) {
					t.Fatalf("maskCached(%q) charged %d bytes", key, maxScanBytes-scan.remaining)
				}
			}
		})
	}
}

func TestKeyCacheFieldMatchesScan(t *testing.T) {
	t.Parallel()
	cached, fresh := NewScanner(WithAll()), NewScanner(WithAll())
	for _, key := range []string{statusKey, credentialFixtureKey, tokenKey, "ssn", "user_id", "phone"} {
		// A pending key is published when it is stored again.
		for range 2 {
			scan := eventScanner{scanner: cached, remaining: maxScanBytes}
			if _, err := scan.maskCached(context.Background(), key); err != nil {
				t.Fatal(err)
			}
		}
		text := []byte(key + ": 663271262 TokenStore@1a2b3c")
		got, ok := cached.cachedField([]byte(key))
		if want := cached.keyField(text, len(key)); !ok || got != want {
			t.Fatalf("cachedField(%q) = %+v, %v; want %+v", key, got, ok, want)
		}
		hit := cached.scanField(text, len(key)+len(": "), nil)
		if miss := fresh.scanField(text, len(key)+len(": "), nil); !slices.Equal(hit, miss) {
			t.Fatalf("%q: cached findings %v, want %v", key, hit, miss)
		}
	}
	if _, ok := NewScanner(WithDetector(&retainingDetector{})).cachedField([]byte(statusKey)); ok {
		t.Fatal("a scanner without a key cache returned a field")
	}
}

func TestKeyCacheKeepsOnlyCleanShortTextKeys(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	for _, key := range []string{statusKey, documentedEmail, "17", strings.Repeat("k", maxCachedKeyBytes+1)} {
		scan := eventScanner{scanner: scanner, remaining: maxScanBytes}
		if _, err := scan.maskCached(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := scanner.keys.load(statusKey); !ok {
		t.Fatal("clean key was not cached")
	}
	for _, key := range []string{documentedEmail, "17", strings.Repeat("k", maxCachedKeyBytes+1)} {
		if _, ok := scanner.keys.load(key); ok {
			t.Fatalf("%q must not be cached", key)
		}
	}
	if got := scanner.keys.size(); got != 1 {
		t.Fatalf("cache size = %d, want 1", got)
	}
	if !scanner.cachedSensitiveKey(credentialFixtureKey) || scanner.cachedSensitiveKey(statusKey) {
		t.Fatal("cached sensitivity disagrees with the key policy")
	}
	if NewScanner(WithDetector(&retainingDetector{})).keys != nil {
		t.Fatal("custom detectors may answer differently, so their scanner must not cache keys")
	}
}

func TestKeyCacheStopsAdmittingWhenFull(t *testing.T) {
	t.Parallel()
	var cache keyCache
	for i := range maxCachedKeys + 10 {
		cache.store("key"+strconv.Itoa(i), keyResult{masked: "kept"})
	}
	cache.store("key0", keyResult{masked: "again"})
	if got := cache.size(); got != maxCachedKeys {
		t.Fatalf("cache size = %d, want %d", got, maxCachedKeys)
	}
	if result, ok := cache.load("key0"); !ok || result.masked != "kept" {
		t.Fatalf("first entry = %+v, %v", result, ok)
	}
	if _, ok := cache.load("key" + strconv.Itoa(maxCachedKeys)); ok {
		t.Fatal("a full cache admitted another key")
	}
}

func TestMaskKeyHitStillChecksCancellationAndBudget(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	warm := eventScanner{scanner: scanner, remaining: maxScanBytes}
	if _, err := warm.maskCached(context.Background(), statusKey); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := warm.maskCached(canceled, statusKey); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatalf("canceled hit = %v", err)
	}
	short := eventScanner{scanner: scanner, remaining: len(statusKey) - 1}
	if _, err := short.maskCached(context.Background(), statusKey); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatalf("hit beyond budget = %v", err)
	}
	exact := eventScanner{scanner: scanner, remaining: len(statusKey)}
	if _, err := exact.maskCached(context.Background(), statusKey); err != nil || exact.remaining != 0 {
		t.Fatalf("hit at the budget = %v, remaining %d", err, exact.remaining)
	}
}

func TestKeyCachePublishesPendingKeysInDoublingBatches(t *testing.T) {
	t.Parallel()
	var cache keyCache
	cache.store("a", keyResult{masked: "a"})
	if _, ok := cache.load("a"); !ok {
		t.Fatal("the first key must be published at once")
	}
	cache.store("b", keyResult{masked: "b"})
	cache.store("c", keyResult{masked: "c"})
	if _, ok := cache.load("c"); ok {
		t.Fatal("a pending key smaller than the published set must wait")
	}
	if got := cache.size(); got != 3 {
		t.Fatalf("size = %d, want 3", got)
	}
	cache.store("c", keyResult{masked: "again"})
	if _, ok := cache.load("c"); !ok {
		t.Fatal("a pending key stored again must publish its batch")
	}
	cache.store("d", keyResult{masked: "d"})
	cache.store("e", keyResult{masked: "e"})
	cache.store("d", keyResult{masked: "d"})
	for _, key := range []string{"a", "b", "c", "d", "e"} {
		if _, ok := cache.load(key); !ok {
			t.Fatalf("%q was not published with its batch", key)
		}
	}
	if result, _ := cache.loadBytes([]byte("c")); result.masked != "c" || result.key != "c" {
		t.Fatalf("a repeated store replaced the pending result: %+v", result)
	}
}
