package tests

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/nao1215/embargo"
)

// The per-byte coverage oracle does not sort or merge intervals.
func TestMaskCoverageOracle(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		length := rapid.IntRange(1, 100).Draw(t, "text length")
		text := strings.Repeat("x", length)
		coverage := make([]bool, length)
		count := rapid.IntRange(0, 30).Draw(t, "span count")
		findings := make([]embargo.Finding, 0, count)
		for range count {
			start := rapid.IntRange(0, length-1).Draw(t, "start")
			end := rapid.IntRange(start+1, length).Draw(t, "end")
			findings = append(findings, embargo.Finding{Kind: "fixture", Start: start, End: end, Confidence: 1})
			for i := start; i < end; i++ {
				coverage[i] = true
			}
		}
		var want strings.Builder
		for _, covered := range coverage {
			if covered {
				//nolint:errcheck // strings.Builder writes always succeed.
				want.WriteByte('*')
			} else {
				//nolint:errcheck // strings.Builder writes always succeed.
				want.WriteByte('x')
			}
		}
		replace := func(_ embargo.Kind, v string) string { return strings.Repeat("*", len(v)) }
		before := slices.Clone(findings)
		if got := embargo.MaskFunc(text, findings, replace); got != want.String() {
			t.Fatalf("union %q != %q", got, want.String())
		}
		if !reflect.DeepEqual(findings, before) {
			t.Fatal("findings mutated")
		}
		slices.Reverse(findings)
		if got := embargo.MaskFunc(text, findings, replace); got != want.String() {
			t.Fatal("permutation changed union")
		}
	})
}
