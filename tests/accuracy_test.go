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
type accuracySpan struct {
	Start int `json:"start"`
	End   int `json:"end"`
}
type labeledAccuracySample struct {
	Kind     embargo.Kind   `json:"kind"`
	Text     string         `json:"text"`
	Parts    []string       `json:"parts"`
	Expected []accuracySpan `json:"expected"`
}
type accuracyCount struct{ tp, fp, tn, fn int }

func scoreAccuracy(kind embargo.Kind, findings []embargo.Finding, expected []accuracySpan) accuracyCount {
	result := accuracyCount{}
	used := make([]bool, len(expected))
	for _, finding := range findings {
		matched := false
		for index, span := range expected {
			if !used[index] && finding.Kind == kind && finding.Start == span.Start && finding.End == span.End {
				used[index] = true
				matched = true
				break
			}
		}
		if matched {
			result.tp++
		} else {
			result.fp++
		}
	}
	for _, matched := range used {
		if !matched {
			result.fn++
		}
	}
	return result
}

func accuracyRatio(numerator, denominator int) string {
	if denominator == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(numerator)/float64(denominator))
}

func TestAccuracyTable(t *testing.T) {
	t.Parallel()
	corpus, err := os.ReadFile("testdata/accuracy.json")
	if err != nil {
		t.Fatal(err)
	}
	var samples []labeledAccuracySample
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
	inputs := map[string][2]int{}

	for _, sample := range samples {
		input := inputs[string(sample.Kind)]
		if len(sample.Expected) == 0 {
			input[1]++
		} else {
			input[0]++
		}
		inputs[string(sample.Kind)] = input
		findings := embargo.NewScanner(embargo.WithKinds(sample.Kind)).ScanString(sample.Text + strings.Join(sample.Parts, ""))
		result := scoreAccuracy(sample.Kind, findings, sample.Expected)
		count := counts[string(sample.Kind)]
		count.tp += result.tp
		count.fp += result.fp
		count.fn += result.fn
		if len(sample.Expected) == 0 && len(findings) == 0 {
			count.tn++
		}
		counts[string(sample.Kind)] = count
	}

	names := make([]string, 0, len(counts))
	for name, count := range counts {
		input := inputs[name]
		input[1] += len(controls)
		inputs[name] = input
		scanner := embargo.NewScanner(embargo.WithKinds(embargo.Kind(name)))
		for _, control := range controls {
			if found := len(scanner.ScanString(control.Text)); found > 0 {
				count.fp += found
			} else {
				count.tn++
			}
		}
		counts[name] = count
		names = append(names, name)
	}
	sort.Strings(names)
	var table strings.Builder
	if _, err := fmt.Fprintln(&table, "| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |\n|---|---:|---:|---:|---:|"); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		count := counts[name]

		if _, err := fmt.Fprintf(&table, "| %s | %d / %d | %d / %d / %d | %s | %s |\n", name, inputs[name][0], inputs[name][1], count.tp, count.fp, count.fn, accuracyRatio(count.tp, count.tp+count.fp), accuracyRatio(count.tp, count.tp+count.fn)); err != nil {
			t.Fatal(err)
		}
	}
	syncReadmeTable(t, "accuracy", table.String())
}

func syncReadmeTable(t *testing.T, name, table string) {
	t.Helper()
	syncDocTable(t, "../README.md", name, table)
}

func syncDocTable(t *testing.T, path, name, table string) {
	t.Helper()
	// #nosec G304 -- callers supply only fixed repository documentation paths.
	data, err := os.ReadFile(path)
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
		if err := os.WriteFile(path, []byte(before+start+table+end+after), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if got != table {
		t.Fatalf("%s table is stale; regenerate its make target", name)
	}
}

func TestAccuracyRequiresExactUnusedSpans(t *testing.T) {
	t.Parallel()
	expected := []accuracySpan{{Start: 1, End: 5}}
	for _, tc := range []struct {
		name     string
		findings []embargo.Finding
		want     accuracyCount
	}{
		{name: "partial", findings: []embargo.Finding{{Kind: embargo.KindEmail, Start: 1, End: 4}}, want: accuracyCount{fp: 1, fn: 1}},
		{name: "wrong kind", findings: []embargo.Finding{{Kind: embargo.KindPAN, Start: 1, End: 5}}, want: accuracyCount{fp: 1, fn: 1}},
		{name: "duplicate", findings: []embargo.Finding{{Kind: embargo.KindEmail, Start: 1, End: 5}, {Kind: embargo.KindEmail, Start: 1, End: 5}}, want: accuracyCount{tp: 1, fp: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := scoreAccuracy(embargo.KindEmail, tc.findings, expected); got != tc.want {
				t.Fatalf("wrong classification: %+v", got)
			}
		})
	}
	if accuracyRatio(0, 0) != "n/a" {
		t.Fatal("undefined precision must not imply zero accuracy")
	}
}
