package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

type accuracySample struct {
	Detector string   `json:"detector"`
	Text     string   `json:"text"`
	Parts    []string `json:"parts"`
	Positive bool     `json:"positive"`
}
type accuracyCount struct{ tp, fp, tn, fn int }

func TestAccuracyTable(t *testing.T) {
	t.Parallel()
	corpus, err := os.ReadFile("../testdata/recall.json")
	if err != nil {
		t.Fatal(err)
	}
	var samples []accuracySample
	if decodeErr := json.Unmarshal(corpus, &samples); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	data, err := os.ReadFile("testdata/accuracy_controls.json")
	if err != nil {
		t.Fatal(err)
	}
	var controls []struct {
		Source string `json:"source"`
		Text   string `json:"text"`
	}
	if err := json.Unmarshal(data, &controls); err != nil {
		t.Fatal(err)
	}
	counts := map[string]accuracyCount{}
	for _, sample := range samples {
		found := len(embargo.NewScanner(embargo.WithKinds(embargo.Kind(sample.Detector))).ScanString(sample.Text+strings.Join(sample.Parts, ""))) > 0
		count := counts[sample.Detector]
		switch {
		case sample.Positive && found:
			count.tp++
		case sample.Positive:
			count.fn++
		case found:
			count.fp++
		default:
			count.tn++
		}
		counts[sample.Detector] = count
	}
	names := make([]string, 0, len(counts))
	for name, count := range counts {
		scanner := embargo.NewScanner(embargo.WithKinds(embargo.Kind(name)))
		for _, control := range controls {
			if len(scanner.ScanString(control.Text)) > 0 {
				count.fp++
			} else {
				count.tn++
			}
		}
		counts[name] = count
		names = append(names, name)
	}
	sort.Strings(names)
	var table strings.Builder
	if _, err := fmt.Fprintln(&table, "| Detector | Positive / negative samples | TP / FP / FN | Precision | Recall |\n|---|---:|---:|---:|---:|"); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		count := counts[name]
		precision, recall := 0.0, 0.0
		if count.tp+count.fp > 0 {
			precision = 100 * float64(count.tp) / float64(count.tp+count.fp)
		}
		if count.tp+count.fn > 0 {
			recall = 100 * float64(count.tp) / float64(count.tp+count.fn)
		}
		if _, err := fmt.Fprintf(&table, "| %s | %d / %d | %d / %d / %d | %.1f%% | %.1f%% |\n", name, count.tp+count.fn, count.fp+count.tn, count.tp, count.fp, count.fn, precision, recall); err != nil {
			t.Fatal(err)
		}
	}
	syncReadmeTable(t, "accuracy", table.String())
}

func syncReadmeTable(t *testing.T, name, table string) {
	t.Helper()
	data, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	start, end := "<!-- "+name+":start -->\n", "<!-- "+name+":end -->"
	before, rest, ok := strings.Cut(string(data), start)
	if !ok {
		t.Fatal("documentation start marker missing")
	}
	got, after, ok := strings.Cut(rest, end)
	if !ok {
		t.Fatal("documentation end marker missing")
	}
	if os.Getenv("UPDATE_DOCS") == "1" {
		// #nosec G703 -- table data cannot change the fixed destination path.
		if err := os.WriteFile("../README.md", []byte(before+start+table+end+after), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if got != table {
		t.Fatalf("%s table is stale; regenerate its make target", name)
	}
}
