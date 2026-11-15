package tests

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

type accuracyLimit struct {
	ID     string         `json:"id"`
	Reason string         `json:"reason"`
	Found  []accuracySpan `json:"found"`
}

type accuracyControl struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Text   string `json:"text"`
}

func allAccuracyControls(t *testing.T) []accuracyControl {
	t.Helper()
	data, err := os.ReadFile("testdata/accuracy_controls.json")
	if err != nil {
		t.Fatal(err)
	}
	//nolint:prealloc // JSON decoding determines the initial slice length.
	var controls []accuracyControl
	if err := json.Unmarshal(data, &controls); err != nil {
		t.Fatal(err)
	}
	for i := range controls {
		controls[i].ID = fmt.Sprintf("hand-control/%x", sha256.Sum256([]byte(controls[i].Source+"\x00"+controls[i].Text)))
	}
	return append(controls, readGeneratedAccuracy[accuracyControl](t, "testdata/accuracy_generated_controls.jsonl")...)
}

func allAccuracySamples(t *testing.T) []labeledAccuracySample {
	t.Helper()
	data, err := os.ReadFile("testdata/accuracy.json")
	if err != nil {
		t.Fatal(err)
	}
	//nolint:prealloc // JSON decoding determines the initial slice length.
	var rows []labeledAccuracySample
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	kinds := map[embargo.Kind]bool{}
	for i := range rows {
		rows[i].ID = fmt.Sprintf("hand/%d", i)
		kinds[rows[i].Kind] = true
	}
	rows = append(rows, readGeneratedAccuracy[labeledAccuracySample](t, "testdata/accuracy_generated.jsonl")...)
	controls := allAccuracyControls(t)
	for kind := range kinds {
		for _, c := range controls {
			rows = append(rows, labeledAccuracySample{ID: string(kind) + "/" + c.ID, Kind: kind, Text: c.Text})
		}
	}
	for i := range rows {
		rows[i].Text += strings.Join(rows[i].Parts, "")
	}
	slices.SortFunc(rows, func(a, b labeledAccuracySample) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return rows
}

func TestGeneratedAccuracyRegressions(t *testing.T) {
	t.Parallel()
	limits := readGeneratedAccuracy[accuracyLimit](t, "testdata/accuracy_limits.jsonl")
	known := map[string]accuracyLimit{}
	for _, limit := range limits {
		if limit.Reason == "" {
			t.Fatal("known limits require a reason")
		}
		if _, ok := known[limit.ID]; ok {
			t.Fatal("duplicate limit")
		}
		known[limit.ID] = limit
	}
	seen := map[string]bool{}
	for _, sample := range allAccuracySamples(t) {
		seen[sample.ID] = true
		findings := embargo.NewScanner(embargo.WithKinds(sample.Kind)).ScanString(sample.Text)
		got := scoreAccuracy(sample.Kind, findings, sample.Expected)
		limit, exists := known[sample.ID]
		if got.fp == 0 && got.fn == 0 {
			if exists {
				t.Errorf("%s: limit no longer applies; remove it after review", sample.ID)
			}
			continue
		}
		spans := make([]accuracySpan, 0, len(findings))
		for _, f := range findings {
			spans = append(spans, accuracySpan{Start: f.Start, End: f.End})
		}
		if !exists || !slices.Equal(spans, limit.Found) {
			t.Errorf("%s: unreviewed FP=%d FN=%d; add a regression/fix or explain the limit", sample.ID, got.fp, got.fn)
		}
	}
	for id := range known {
		if !seen[id] {
			t.Errorf("orphan limit %s", id)
		}
	}
}
