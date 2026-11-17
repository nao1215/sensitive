package embargo

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/saferecord"
)

func TestMaskKeyCacheHitMatchesScan(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	for _, key := range []string{"status", "password", "alice@example.com", "17", "-1", strings.Repeat("k", maxCachedKeyBytes+1)} {
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

func TestKeyCacheKeepsOnlyCleanShortTextKeys(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	for _, key := range []string{"status", "alice@example.com", "17", strings.Repeat("k", maxCachedKeyBytes+1)} {
		scan := eventScanner{scanner: scanner, remaining: maxScanBytes}
		if _, err := scan.maskCached(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := scanner.keys.load("status"); !ok {
		t.Fatal("clean key was not cached")
	}
	for _, key := range []string{"alice@example.com", "17", strings.Repeat("k", maxCachedKeyBytes+1)} {
		if _, ok := scanner.keys.load(key); ok {
			t.Fatalf("%q must not be cached", key)
		}
	}
	if got := scanner.keys.size(); got != 1 {
		t.Fatalf("cache size = %d, want 1", got)
	}
	if !scanner.cachedSensitiveKey("password") || scanner.cachedSensitiveKey("status") {
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
		cache.store("key"+strconv.Itoa(i), keyResult{masked: "key"})
	}
	cache.store("key0", keyResult{masked: "again"})
	if got := cache.size(); got != maxCachedKeys {
		t.Fatalf("cache size = %d, want %d", got, maxCachedKeys)
	}
	if result, ok := cache.load("key0"); !ok || result.masked != "key" {
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
	if _, err := warm.maskCached(context.Background(), "status"); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := warm.maskCached(canceled, "status"); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatalf("canceled hit = %v", err)
	}
	short := eventScanner{scanner: scanner, remaining: len("status") - 1}
	if _, err := short.maskCached(context.Background(), "status"); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatalf("hit beyond budget = %v", err)
	}
	exact := eventScanner{scanner: scanner, remaining: len("status")}
	if _, err := exact.maskCached(context.Background(), "status"); err != nil || exact.remaining != 0 {
		t.Fatalf("hit at the budget = %v, remaining %d", err, exact.remaining)
	}
}
