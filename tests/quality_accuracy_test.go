package tests

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/nao1215/embargo"
)

type qualityFloor struct {
	Set  string       `json:"set"`
	Kind embargo.Kind `json:"kind"`
	TP   int64        `json:"tp"`
	FP   int64        `json:"fp"`
	FN   int64        `json:"fn"`
}

func meetsQualityFloor(actual accuracyCount, floor qualityFloor) bool {
	tp, fp, fn := int64(actual.tp), int64(actual.fp), int64(actual.fn)
	return tp+fp > 0 && tp+fn > 0 && tp*(floor.TP+floor.FP) >= floor.TP*(tp+fp) && tp*(floor.TP+floor.FN) >= floor.TP*(tp+fn)
}

func TestQualityAccuracy(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../doc/quality-gates.json")
	if err != nil {
		t.Fatal(err)
	}
	var gates struct {
		Accuracy              []qualityFloor `json:"accuracy"`
		CriticalResidualBytes int            `json:"critical_residual_bytes"`
	}
	if err := json.Unmarshal(data, &gates); err != nil {
		t.Fatal(err)
	}
	if len(gates.Accuracy) == 0 || gates.CriticalResidualBytes != 0 {
		t.Fatal("missing floors or weakened critical exposure contract")
	}
	for _, set := range []string{developmentAccuracySet, heldAccuracySet} {
		samples := allAccuracySamples(t, set)
		samples = append(samples, readGeneratedAccuracy[labeledAccuracySample](t, "testdata/credentials-"+set+".jsonl")...)
		samples = append(samples, countrySamples(t, set)...)
		scanners := map[embargo.Kind]*embargo.Scanner{}
		counts := map[embargo.Kind]accuracyCount{}
		residual := map[embargo.Kind]int{}
		for _, sample := range samples {
			findings := accuracyScanner(scanners, sample.Kind, 0).ScanString(sample.Text)
			scored := scoreAccuracy(sample.Kind, findings, sample.Expected)
			count := counts[sample.Kind]
			count.tp += scored.tp
			count.fp += scored.fp
			count.fn += scored.fn
			counts[sample.Kind] = count
			for _, n := range residualBytes([]byte(sample.Text), findings, sample.Expected) {
				residual[sample.Kind] += n
			}
		}
		seen := map[embargo.Kind]bool{}
		for _, floor := range gates.Accuracy {
			if floor.Set != set {
				continue
			}
			actual, exists := counts[floor.Kind]
			if !exists || seen[floor.Kind] || floor.TP <= 0 || floor.FP < 0 || floor.FN < 0 {
				t.Fatal("invalid floor or missing corpus", set, floor.Kind)
			}
			seen[floor.Kind] = true
			t.Logf("%s/%s precision %s >= %s; recall %s >= %s", set, floor.Kind, accuracyRatio(actual.tp, actual.tp+actual.fp), accuracyRatio(int(floor.TP), int(floor.TP+floor.FP)), accuracyRatio(actual.tp, actual.tp+actual.fn), accuracyRatio(int(floor.TP), int(floor.TP+floor.FN)))
			if !meetsQualityFloor(actual, floor) {
				t.Errorf("accuracy floor failed: %s/%s tp=%d fp=%d fn=%d; floor tp=%d fp=%d fn=%d", set, floor.Kind, actual.tp, actual.fp, actual.fn, floor.TP, floor.FP, floor.FN)
			}
			if severity(floor.Kind) == criticalTier && residual[floor.Kind] > gates.CriticalResidualBytes {
				t.Errorf("critical residual exposure: %s/%s bytes=%d", set, floor.Kind, residual[floor.Kind])
			}
		}
		if len(seen) != len(counts) {
			t.Fatal("a corpus Kind has no explicit floor", set)
		}
	}
}

func TestQualityFloorRejectsPrecisionAndRecallLoss(t *testing.T) {
	t.Parallel()
	floor := qualityFloor{TP: 90, FP: 10, FN: 10}
	for _, tc := range []struct {
		name   string
		actual accuracyCount
		want   bool
	}{
		{"equal ratios", accuracyCount{tp: 180, fp: 20, fn: 20}, true},
		{"improvement", accuracyCount{tp: 100}, true},
		{"precision loss", accuracyCount{tp: 90, fp: 11, fn: 10}, false},
		{"recall loss", accuracyCount{tp: 89, fp: 9, fn: 11}, false},
		{"empty measurement", accuracyCount{}, false},
	} {
		if meetsQualityFloor(tc.actual, floor) != tc.want {
			t.Fatal(tc.name)
		}
	}
}
