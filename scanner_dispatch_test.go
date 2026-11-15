package embargo

import (
	"math/rand/v2"
	"slices"
	"testing"
)

// The pre-optimization dispatch loop remains test-only, using the same detectors
// so that deliberate accuracy changes do not masquerade as optimization drift.
func referenceScan(s *Scanner, data []byte) []Finding {
	data, positions := decodePercent(data)
	var out []Finding
	var folded []byte
	var ready bool
	for i, d := range s.detectors {
		if !matchesAnyHint(s.hintCache[i], data, &folded, &ready) {
			continue
		}
		for _, f := range d.Scan(data) {
			if positions != nil {
				f.Start, f.End = positions[f.Start], positions[f.End]
			}
			if f.Confidence >= s.minConfidence {
				out = append(out, Finding{Kind: Kind(f.DetectorName), Start: f.Start, End: f.End, Confidence: f.Confidence})
			}
		}
	}
	slices.SortStableFunc(out, compareFindings)
	return out
}

func TestDispatchDifferential(t *testing.T) {
	t.Parallel()
	// #nosec G404 -- Fixed seed for reproducible synthetic tests.
	rng := rand.New(rand.NewPCG(72, 54))
	parts := []string{"foo", "@", "ABC", "0123456789", " ", "\n", "銀行", "４２４２", "expiry 12/29", "CVV 123", "a+b@example.com", "SWIFT: DEUTDEFF", "%20", "bank account 12345678", "4242424242424242", "090-1234-5678", "ghp_", "\xff", "sort code 40-12-36"}
	for _, s := range []*Scanner{NewScanner(), NewScanner(WithKinds(KindEmail)), NewScanner(WithMinConfidence(.7)), NewScanner(WithKinds())} {
		for i := range 3000 {
			var data []byte
			for range rng.IntN(15) {
				data = append(data, parts[rng.IntN(len(parts))]...)
			}
			if i%3 == 0 {
				data = append(data, byte(rng.IntN(256))) // #nosec G115 -- IntN is bounded to a byte.
			}
			got, want := s.Scan(data), referenceScan(s, data)
			if !slices.Equal(got, want) {
				t.Fatalf("input %q\ngot %+v\nwant %+v", data, got, want)
			}
		}
	}
}

//nolint:paralleltest // AllocsPerRun changes GOMAXPROCS while measuring.
func TestCleanScanAllocationBudget(t *testing.T) {
	s := NewScanner()
	data := []byte("worker completed request reference=example\n")
	if got := testing.AllocsPerRun(100, func() { s.Scan(data) }); got != 0 {
		t.Fatalf("clean input allocated %.0f times", got)
	}
}

func TestDispatchExhaustiveNumericAndTerminalHints(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind  Kind
		input string
		end   int
	}{
		{KindMyNumber, "111111111118", 12},
		{KindABARouting, "111111118", 9},
		{KindCVV, "123 CVV", 3},
		{KindBankAccount, "12345678 bank account", 8},
		{KindACHTrace, "021000021123456 ACH trace", 15},
	} {
		for _, scanner := range []*Scanner{NewScanner(WithKinds(tc.kind)), NewScanner(WithAll())} {
			got := scanner.ScanString(tc.input)
			if len(got) != 1 || got[0].Kind != tc.kind || got[0].Start != 0 || got[0].End != tc.end {
				t.Fatal(tc.kind, got)
			}
		}
	}
}
