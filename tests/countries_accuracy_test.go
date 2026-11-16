package tests

import (
	"slices"
	"testing"

	"github.com/nao1215/embargo"
)

type countryResult struct {
	Set           string       `json:"set"`
	Kind          embargo.Kind `json:"kind"`
	Precision     string       `json:"precision"`
	Recall        string       `json:"recall"`
	Threshold     float64      `json:"threshold"`
	TP            int          `json:"tp"`
	FP            int          `json:"fp"`
	FN            int          `json:"fn"`
	ResidualBytes int          `json:"residual_bytes"`
}

func countrySamples(t *testing.T, set string) []labeledAccuracySample {
	t.Helper()
	return readGeneratedAccuracy[labeledAccuracySample](t, "testdata/countries-"+set+".jsonl")
}

func TestCountryAccuracy(t *testing.T) {
	t.Parallel()
	results := make([]countryResult, 0, 66)
	for _, set := range []string{developmentAccuracySet, heldAccuracySet} {
		samples := countrySamples(t, set)
		for _, threshold := range []float64{0, .5, .7} {
			scanners := map[embargo.Kind]*embargo.Scanner{}
			counts := map[embargo.Kind]countryResult{}
			for _, sample := range samples {
				findings := accuracyScanner(scanners, sample.Kind, threshold).ScanString(sample.Text)
				score := scoreAccuracy(sample.Kind, findings, sample.Expected)
				count := counts[sample.Kind]
				count.Set = set
				count.Kind = sample.Kind
				count.Threshold = threshold
				count.TP += score.tp
				count.FP += score.fp
				count.FN += score.fn
				for _, n := range residualBytes([]byte(sample.Text), findings, sample.Expected) {
					count.ResidualBytes += n
				}
				counts[sample.Kind] = count
			}
			kinds := make([]embargo.Kind, 0, len(counts))
			for kind := range counts {
				kinds = append(kinds, kind)
			}
			slices.Sort(kinds)
			for _, kind := range kinds {
				count := counts[kind]
				count.Precision = accuracyRatio(count.TP, count.TP+count.FP)
				count.Recall = accuracyRatio(count.TP, count.TP+count.FN)
				results = append(results, count)
			}
		}
	}
	syncSeverityJSON(t, "../doc/countries.json", results)
}
