package tests

import (
	"bufio"
	"bytes"
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
	ID       string         `json:"id"`
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
	samples := allAccuracySamples(t)

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
		findings := embargo.NewScanner(embargo.WithKinds(sample.Kind)).ScanString(sample.Text)
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
	for name := range counts {
		names = append(names, name)
	}

	sort.Strings(names)
	summaries := make([]accuracySummary, 0, len(names))
	for _, name := range names {
		count := counts[name]
		summaries = append(summaries, accuracySummary{Detector: name, Positive: inputs[name][0], Negative: inputs[name][1], TP: count.tp, FP: count.fp, FN: count.fn, Precision: accuracyRatio(count.tp, count.tp+count.fp), Recall: accuracyRatio(count.tp, count.tp+count.fn)})
	}
	syncAccuracySnapshot(t, summaries)
	syncReadmeTable(t, "accuracy", accuracyEntrance(t, names))
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

func readGeneratedAccuracy[T any](t *testing.T, path string) []T {
	t.Helper()
	// #nosec G304 -- callers supply only repository fixture paths.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []T
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		var row T
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}

type accuracySummary struct {
	Detector  string `json:"detector"`
	Precision string `json:"precision"`
	Recall    string `json:"recall"`
	Positive  int    `json:"positive"`
	Negative  int    `json:"negative"`
	TP        int    `json:"tp"`
	FP        int    `json:"fp"`
	FN        int    `json:"fn"`
}

func writeAccuracyText(t *testing.T, out *strings.Builder, value string) {
	t.Helper()
	if _, err := out.WriteString(value); err != nil {
		t.Fatal(err)
	}
}

func syncAccuracySnapshot(t *testing.T, rows []accuracySummary) {
	t.Helper()
	//nolint:errchkjson // Keep encoding failure handling explicit for future snapshot fields.
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	const path = "../doc/accuracy.json"
	if os.Getenv("UPDATE_DOCS") == "1" {
		if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		return
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(actual, []byte("\r\n"), []byte("\n")), data) {
		t.Fatal("accuracy snapshot differs from scored corpus; run make accuracy-doc")
	}
}

func accuracyEntrance(t *testing.T, names []string) string {
	t.Helper()
	var entrance strings.Builder
	if _, err := entrance.WriteString("![Precision and recall on synthetic samples](doc/images/accuracy.svg)\n\n| Detector details | | |\n|---|---|---|\n"); err != nil {
		t.Fatal(err)
	}
	for index, name := range names {
		if index%3 == 0 {
			writeAccuracyText(t, &entrance, "|")
		}
		if _, err := fmt.Fprintf(&entrance, " [%s](doc/accuracy.md#%s) |", name, strings.ReplaceAll(name, "_", "-")); err != nil {
			t.Fatal(err)
		}
		if index%3 == 2 {
			writeAccuracyText(t, &entrance, "\n")
		}
	}
	if len(names)%3 != 0 {
		for index := len(names) % 3; index < 3; index++ {
			writeAccuracyText(t, &entrance, " |")
		}
		writeAccuracyText(t, &entrance, "\n")
	}
	return entrance.String()
}
