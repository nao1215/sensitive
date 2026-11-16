package tests

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

func TestAdoptionCheckIndependence(t *testing.T) {
	t.Parallel()
	var table strings.Builder
	writeComparisonTable(t, &table, "| Output after embargo masking | Detector only | Whole canary only | Canary with 16-byte fragments |\n|---|---|---|---|\n")
	for _, tc := range adoptionCases() {
		output := adoptionOutput(t, tc, comparisonEmbargoName)
		writeComparisonTable(t, &table, "| %s |", tc.name)
		for mode := range 3 {
			probe := &observationTB{TB: t}
			options := []embargotest.Option{embargotest.WithCanary([]byte(tc.canary))}
			want := tc.name == "unwrapped logger"
			if mode == 0 {
				options = []embargotest.Option{embargotest.WithCanary([]byte("unrelated-fixture-XYZ-987654321"))}
			} else {
				options = append(options, embargotest.WithScanner(embargo.NewScanner(embargo.WithKinds())))
				want = want || tc.name == "base64 token" || tc.name == "hex token"
			}
			if mode == 2 {
				options = append(options, embargotest.WithCanaryFragments(16))
				want = want || tc.name == "split token lines"
			}
			recorder := embargotest.New(probe, options...)
			if _, err := recorder.Writer("logs").Write(output); err != nil {
				t.Fatal(err)
			}
			recorder.Expect("logs", func(b []byte) bool { return bytes.Contains(b, []byte(caseOrder)) })
			detected := !recorder.Check()
			probe.finish()
			if detected != want {
				t.Fatalf("%s mode %d: detected=%t, want %t", tc.name, mode, detected, want)
			}
			result := "clear"
			if detected {
				result = "detected"
			}
			writeComparisonTable(t, &table, " %s |", result)
		}
		writeComparisonTable(t, &table, "\n")
	}
	syncDocTable(t, "../doc/testing-output.md", "check-independence", table.String())
}
