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

// statusKey is a clean field name and tokenKey a credential one;
// acceptedValue is a clean value.
const (
	statusKey     = "status"
	tokenKey      = "token"
	acceptedValue = "accepted"
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
				got, sensitive, err := scan.maskCached(context.Background(), key)
				if got != want || !errors.Is(err, wantErr) || sensitive != scanner.sensitiveKey(key) {
					t.Fatalf("maskCached(%q) = %q, %v, %v; want %q, %v", key, got, sensitive, err, want, wantErr)
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
			if _, _, err := scan.maskCached(context.Background(), key); err != nil {
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
		if _, _, err := scan.maskCached(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	if scanner.keys.load(statusKey) == nil {
		t.Fatal("clean key was not cached")
	}
	for _, key := range []string{documentedEmail, "17", strings.Repeat("k", maxCachedKeyBytes+1)} {
		if scanner.keys.load(key) != nil {
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
		cache.store("key"+strconv.Itoa(i), keyResult{sensitive: true})
	}
	cache.store("key0", keyResult{})
	if got := cache.size(); got != maxCachedKeys {
		t.Fatalf("cache size = %d, want %d", got, maxCachedKeys)
	}
	if result := cache.load("key0"); result == nil || !result.sensitive {
		t.Fatalf("first entry = %+v", result)
	}
	if cache.load("key"+strconv.Itoa(maxCachedKeys)) != nil {
		t.Fatal("a full cache admitted another key")
	}
}

func TestMaskKeyHitStillChecksCancellationAndBudget(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	warm := eventScanner{scanner: scanner, remaining: maxScanBytes}
	if _, _, err := warm.maskCached(context.Background(), statusKey); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := warm.maskCached(canceled, statusKey); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatalf("canceled hit = %v", err)
	}
	short := eventScanner{scanner: scanner, remaining: len(statusKey) - 1}
	if _, _, err := short.maskCached(context.Background(), statusKey); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatalf("hit beyond budget = %v", err)
	}
	exact := eventScanner{scanner: scanner, remaining: len(statusKey)}
	if _, _, err := exact.maskCached(context.Background(), statusKey); err != nil || exact.remaining != 0 {
		t.Fatalf("hit at the budget = %v, remaining %d", err, exact.remaining)
	}
}

func TestKeyCachePublishesPendingKeysInDoublingBatches(t *testing.T) {
	t.Parallel()
	var cache keyCache
	cache.store("a", keyResult{})
	if cache.load("a") == nil {
		t.Fatal("the first key must be published at once")
	}
	cache.store("b", keyResult{})
	cache.store("c", keyResult{sensitive: true})
	if cache.load("c") != nil {
		t.Fatal("a pending key smaller than the published set must wait")
	}
	if got := cache.size(); got != 3 {
		t.Fatalf("size = %d, want 3", got)
	}
	cache.store("c", keyResult{})
	if cache.load("c") == nil {
		t.Fatal("a pending key stored again must publish its batch")
	}
	cache.store("d", keyResult{})
	cache.store("e", keyResult{})
	cache.store("d", keyResult{})
	for _, key := range []string{"a", "b", "c", "d", "e"} {
		if cache.load(key) == nil {
			t.Fatalf("%q was not published with its batch", key)
		}
	}
	if result := cache.loadBytes([]byte("c")); result == nil || !result.sensitive || result.key != "c" {
		t.Fatalf("a repeated store replaced the pending result: %+v", result)
	}
}

func TestValueCacheHitMatchesScan(t *testing.T) {
	t.Parallel()
	cached, fresh := NewScanner(), NewScanner()
	fresh.values = nil
	pairs := [][2]string{{statusKey, acceptedValue}, {"ok", strconv.FormatBool(true)}, {"count", "17"}, {tokenKey, acceptedValue}, {statusKey, documentedEmail}, {"pan", "4111111111111111"}, {"", acceptedValue}, {statusKey, "YWxpY2VAZXhhbXBsZS5jb20="}}
	for range 3 {
		for _, pair := range pairs {
			hit := eventScanner{scanner: cached, remaining: maxScanBytes}
			miss := eventScanner{scanner: fresh, remaining: maxScanBytes}
			got, gotErr := hit.maskScalar(context.Background(), pair[1], pair[0])
			want, wantErr := miss.maskScalar(context.Background(), pair[1], pair[0])
			if got != want || !errors.Is(gotErr, wantErr) || hit.remaining != miss.remaining {
				t.Fatalf("%q: %q: cached %q, %v, charged %d; want %q, %v, charged %d", pair[0], pair[1], got, gotErr, maxScanBytes-hit.remaining, want, wantErr, maxScanBytes-miss.remaining)
			}
		}
	}
	if !cached.values.has([]byte("status: accepted"), len("status: ")) {
		t.Fatal("a repeated clean value was not cached")
	}
	for _, text := range []string{"status: " + documentedEmail, "pan: 4111111111111111", "token: accepted"} {
		if cached.values.has([]byte(text), strings.Index(text, " ")+1) {
			t.Fatalf("%q has findings and must not be cached", text)
		}
	}
	if NewScanner(WithDetector(&retainingDetector{})).values != nil {
		t.Fatal("custom detectors may answer differently, so their scanner must not cache values")
	}
}

func TestValueCacheKeepsATextSeenTwiceAtItsSlot(t *testing.T) {
	t.Parallel()
	cache := newValueCache()
	text := []byte("status: accepted")
	cache.store(text, 8)
	if cache.has(text, 8) {
		t.Fatal("a text seen once was kept")
	}
	cache.store(text, 8)
	if !cache.has(text, 8) || cache.has(text, 0) || cache.has([]byte("status: rejected"), 8) {
		t.Fatal("the cache must match the text and its prefix")
	}
	long := []byte(strings.Repeat("v", maxCachedValueBytes+1))
	cache.store(long, 0)
	cache.store(long, 0)
	if cache.has(long, 0) {
		t.Fatal("a text over the length limit was kept")
	}
	edge := long[:maxCachedValueBytes]
	cache.store(edge, 0)
	cache.store(edge, 0)
	if !cache.has(edge, 0) {
		t.Fatal("a text at the length limit was not kept")
	}
	// A second text at the same slot replaces the first only once it repeats.
	slot, _ := cache.slot(text)
	var other []byte
	for i := 0; other == nil; i++ {
		candidate := []byte("status: " + strconv.Itoa(i))
		if index, _ := cache.slot(candidate); index == slot {
			other = candidate
		}
	}
	cache.store(other, 8)
	if !cache.has(text, 8) || cache.has(other, 8) {
		t.Fatal("one sighting of another text replaced the kept one")
	}
	cache.store(other, 8)
	if cache.has(text, 8) || !cache.has(other, 8) {
		t.Fatal("a repeated text did not replace the one at its slot")
	}
}

func TestValueCacheConcurrentEvents(t *testing.T) {
	t.Parallel()
	scanner := NewScanner()
	done := make(chan string)
	for worker := range 8 {
		go func() {
			for i := range 200 {
				scan := eventScanner{scanner: scanner, remaining: maxScanBytes}
				value := acceptedValue
				if (i+worker)%3 == 0 {
					value = documentedEmail
				}
				masked, err := scan.maskScalar(context.Background(), value, statusKey)
				if err != nil || (value == documentedEmail) == (masked == value) {
					done <- value + " became " + masked
					return
				}
			}
			done <- ""
		}()
	}
	for range 8 {
		if failure := <-done; failure != "" {
			t.Fatal(failure)
		}
	}
}
