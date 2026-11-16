package embargo

import (
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The pre-optimization dispatch loop remains test-only, using the same detectors
// so that deliberate accuracy changes do not masquerade as optimization drift.
func referenceScan(s *Scanner, data []byte) []Finding {
	original := data
	data, positions := decodePercent(data)
	var out []Finding
	var folded []byte
	var ready bool
	for i, d := range s.detectors {
		if !matchesAnyHint(s.hintCache[i], data, &folded, &ready) {
			continue
		}
		input := data
		if Kind(d.Name()) == KindCredential {
			input = original
		}
		for _, f := range d.Scan(input) {
			if positions != nil && Kind(d.Name()) != KindCredential {
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
			got := slices.DeleteFunc(scanner.ScanString(tc.input), func(f Finding) bool { return f.Kind != tc.kind })
			if len(got) != 1 || got[0].Kind != tc.kind || got[0].Start != 0 || got[0].End != tc.end {
				t.Fatal(tc.kind, got)
			}
		}
	}
}

// The README states how many detectors exist and how many NewScanner runs; a new
// kind must update that sentence in the same change.
func TestReadmeDetectorCounts(t *testing.T) {
	t.Parallel()
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%d built-in detectors (%d run by default)", len(builtins()), len(NewScanner().detectors))
	if !strings.Contains(string(readme), want) {
		t.Fatalf("README must say %q", want)
	}
	if overview := fmt.Sprintf("[%d built-in detectors](", len(builtins())); !strings.Contains(string(readme), overview) {
		t.Fatalf("README overview must link %q", overview)
	}
	_, table, found := strings.Cut(string(readme), "| Group | Detectors | What is detected |\n|---|---:|---|\n")
	if !found {
		t.Fatal("README detector group table not found")
	}
	total := 0
	for row := range strings.Lines(table) {
		cells := strings.Split(row, "|")
		if len(cells) < 4 {
			break
		}
		n, err := strconv.Atoi(strings.TrimSpace(cells[2]))
		if err != nil {
			t.Fatalf("README group row %q: %v", row, err)
		}
		total += n
	}
	if total != len(builtins()) {
		t.Fatalf("README detector groups add up to %d, want %d", total, len(builtins()))
	}
}
