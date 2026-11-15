package embargo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const (
	nestedPercentPrefix = "%252525"
	digitSeparatorRun   = "9 - "
	ibanPrefixRun       = "DE00 "
	credentialPrefixRun = "password="
)

// These cases define the encoding boundary, including unsupported disguises.
func TestAdversarialEncodingBoundary(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	for _, tc := range []struct {
		name, text string
		caught     bool
	}{
		{"plain", "alice@example.com", true},
		{"percent", "alice%40example.com", true},
		{"double-percent", "alice%2540example.com", false},
		{"base64", "YWxpY2VAZXhhbXBsZS5jb20=", false},
		{"zero-width", "alice@exam\u200bple.com", false},
		{"homoglyph", "alice＠example.com", false},
		{"forged-marker", "[REDACTED] alice@example.com", true},
		{"fake-finding", "{Kind:email Start:0 End:99} alice@example.com", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := scanner.ScanString(tc.text); (len(got) > 0) != tc.caught {
				t.Fatal("documented encoding boundary changed")
			}
		})
	}
	masked, err := scanner.MaskJSON([]byte(`{"value":"alice\u0040example.com"}`))
	if err != nil || bytes.Contains(masked, []byte("alice")) {
		t.Fatal("JSON escape bypass")
	}
	// An attacker-controlled audit ID may be masked even when it is not PII.
	scoped := NewScanner(WithKinds(), WithSensitiveKeys("password"))
	document := []byte(`{"audit_id":"alice@example.com","password":"opaque-value"}`)
	masked, err = scoped.MaskJSON(document)
	if err != nil || !bytes.Contains(masked, []byte("alice@example.com")) || bytes.Contains(masked, []byte("opaque-value")) {
		t.Fatal("scoped policy lost audit field or exposed declared secret")
	}
}

func TestAdversarialJSONLimits(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithAll())
	for _, depth := range []int{63, 64, 65, 10000} {
		input := []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
		out, err := scanner.MaskJSON(input)
		if depth <= 64 {
			if err != nil || !json.Valid(out) {
				t.Fatal("valid bounded tree rejected")
			}
		} else if out != nil || err == nil || err.Error() != "embargo: invalid or unmaskable JSON" {
			t.Fatal("deep tree did not fail closed")
		}
	}
	for _, size := range []int{1 << 20, 16 << 20} {
		input := []byte(`{"value":"` + strings.Repeat("x", size) + `"}`)
		out, err := scanner.MaskJSON(input)
		if out != nil || err == nil {
			t.Fatal("oversized document accepted")
		}
	}
	wide := []byte("[" + strings.Repeat(`{"password":"opaque","count":1},`, 1000) + "null]")
	out, err := scanner.MaskJSON(wide)
	if err != nil || !json.Valid(out) || bytes.Contains(out, []byte("opaque")) || bytes.Count(out, []byte(`"count":1`)) != 1000 {
		t.Fatal("wide JSON lost public fields or retained a secret")
	}
}

//nolint:paralleltest // Process-wide allocation accounting must run without concurrent tests.
func TestAdversarialAllocationBudget(t *testing.T) {
	for _, pattern := range []string{digitSeparatorRun, credentialPrefixRun, nestedPercentPrefix, ibanPrefixRun, "=== RUN   fake\n"} {
		data := []byte(strings.Repeat(pattern, (64<<10)/len(pattern)))
		for _, detector := range builtins() {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			detector.Scan(data)
			runtime.ReadMemStats(&after)
			if after.TotalAlloc-before.TotalAlloc > uint64(len(data))*128+1<<20 {
				t.Fatalf("allocation amplification in %s", detector.Name())
			}
		}
	}
}

// Scheduled measurements cover every detector and the public output boundaries.
// Times are reported, while deterministic allocation properties are hard gates.
//
//nolint:gocognit // Keep the same matrix inputs visible across all public paths.
func BenchmarkAdversarialScaling(b *testing.B) {
	b.Run("MaskDense", benchmarkAdversarialMaskRanges)
	for _, pattern := range []string{digitSeparatorRun, credentialPrefixRun, nestedPercentPrefix, "DE00 "} {
		for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
			data := []byte(strings.Repeat(pattern, size/len(pattern)))
			scanners := map[string]*Scanner{"all": NewScanner(WithAll())}
			for _, detector := range builtins() {
				scanners[string(detector.Name())] = NewScanner(WithKinds(Kind(detector.Name())))
			}
			for name, scanner := range scanners {
				b.Run(fmt.Sprintf("%s/%s/%d", name, pattern, size), func(b *testing.B) {
					b.SetBytes(int64(len(data)))
					b.ReportAllocs()
					for b.Loop() {
						scanner.Scan(data)
					}
				})
			}
			scanner := scanners["all"]
			b.Run(fmt.Sprintf("Mask/%s/%d", pattern, size), func(b *testing.B) {
				text := string(data)
				findings := scanner.Scan(data)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					Mask(text, findings)
				}
			})
			b.Run(fmt.Sprintf("MaskJSON/%s/%d", pattern, size), func(b *testing.B) {
				document, err := json.Marshal(string(data))
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if _, err := scanner.MaskJSON(document); err != nil && len(document) <= maxEventBytes {
						b.Fatal(err)
					}
				}
			})
			b.Run(fmt.Sprintf("slog/%s/%d", pattern, size), func(b *testing.B) {
				//nolint:sloglint // This benchmark must include JSON encoding.
				handler := NewSlogHandler(slog.NewJSONHandler(io.Discard, nil), scanner)
				record := slog.Record{Message: string(data)}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if err := handler.Handle(context.Background(), record); err != nil && len(data) < maxEventBytes/2 {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// Empty finding slices do not exercise copying, sorting or range replacement.
func benchmarkAdversarialMaskRanges(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
		text := strings.Repeat("x", size)
		findings := make([]Finding, 0, size/32)
		for start := 0; start+8 <= size; start += 32 {
			findings = append(findings, Finding{Kind: KindEmail, Start: start, End: start + 8, Confidence: 1})
		}
		for _, order := range []string{"forward", "reverse"} {
			if order == "reverse" {
				slices.Reverse(findings)
			}
			b.Run(fmt.Sprintf("%s/%d", order, size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					Mask(text, findings)
				}
			})
		}
	}
}
