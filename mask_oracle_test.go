package embargo

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// A bitmap oracle avoids repeating Mask's interval sorting and merging.
//
//nolint:gocognit // Keep the independent bitmap and invalid-range oracle in one test.
func TestMaskByteCoverageOracle(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(14, 81)) // #nosec G404 -- Reproducible synthetic test data.
	for trial := range 1000 {
		length := rng.IntN(129)
		original := make([]byte, length)
		for i := range original {
			original[i] = byte(rng.IntN(256)) // #nosec G115 -- IntN(256) fits in one byte.
		}
		covered := make([]bool, length)
		var findings []Finding
		invalid := false
		for range rng.IntN(32) {
			start, end := rng.IntN(length+3)-1, rng.IntN(length+3)-1
			if trial%2 == 0 && length > 0 {
				start = rng.IntN(length)
				end = start + 1 + rng.IntN(length-start)
			}
			findings = append(findings, Finding{Kind: KindEmail, Start: start, End: end, Confidence: 1})
			if start < 0 || end > length || start >= end {
				invalid = true
				continue
			}
			for i := start; i < end; i++ {
				covered[i] = true
			}
		}
		want := bytes.Clone(original)
		for i, hidden := range covered {
			if hidden {
				want[i] = '*'
			}
		}
		if invalid {
			want = []byte(redactionMarker)
		}
		before := slices.Clone(findings)
		for range 2 {
			got := MaskFunc(string(original), findings, func(_ Kind, value string) string { return strings.Repeat("*", len(value)) })
			if got != string(want) {
				t.Fatalf("byte-union oracle disagrees at trial %d", trial)
			}
			if !slices.Equal(findings, before) {
				t.Fatal("masking mutated findings")
			}
			slices.Reverse(findings)
			slices.Reverse(before)
		}
	}
}
