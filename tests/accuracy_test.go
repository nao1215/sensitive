package tests

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

const (
	developmentAccuracySet = "development"
	heldAccuracySet        = "held"
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
	for _, set := range selectedAccuracySets(t) {
		for _, threshold := range []float64{0, .5, .7} {
			t.Run(fmt.Sprintf("%s/%.1f", set, threshold), func(t *testing.T) { t.Parallel(); scoreAccuracyTable(t, set, threshold) })
		}
	}
}

func scoreAccuracyTable(t *testing.T, set string, threshold float64) {
	t.Helper()
	samples := allAccuracySamples(t, set)

	scanners := map[embargo.Kind]*embargo.Scanner{}
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
		findings := accuracyScanner(scanners, sample.Kind, threshold).ScanString(sample.Text)
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
	syncAccuracySnapshot(t, set, threshold, summaries)
	if set == heldAccuracySet && threshold == 0 {
		syncReadmeTable(t, "accuracy", accuracyEntrance(t, names))
	}
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

func syncAccuracySnapshot(t *testing.T, set string, threshold float64, rows []accuracySummary) {
	t.Helper()
	//nolint:errchkjson // Keep encoding failure handling explicit for future snapshot fields.
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := "../doc/accuracy"
	if set == heldAccuracySet {
		path += "-held"
	}
	if threshold > 0 {
		path += fmt.Sprintf("-%02.0f", threshold*100)
	}
	path += ".json"
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
	if _, err := entrance.WriteString("[Per-detector precision, recall and charts](doc/accuracy.md).\n\n| Detector details | | |\n|---|---|---|\n"); err != nil {
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

// Each table has one immutable scanner per kind and threshold; fixtures never change its options.
func accuracyScanner(scanners map[embargo.Kind]*embargo.Scanner, kind embargo.Kind, threshold float64) *embargo.Scanner {
	scanner := scanners[kind]
	if scanner == nil {
		scanner = embargo.NewScanner(embargo.WithKinds(kind), embargo.WithMinConfidence(threshold))
		scanners[kind] = scanner
	}
	return scanner
}

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

func allAccuracyControls(t *testing.T, set string) []accuracyControl {
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
	if set == heldAccuracySet {
		controls = nil
	}
	for i := range controls {
		controls[i].ID = fmt.Sprintf("hand-control/%x", sha256.Sum256([]byte(controls[i].Source+"\x00"+controls[i].Text)))
	}
	return append(controls, readGeneratedAccuracy[accuracyControl](t, accuracyFixture(set, "testdata/accuracy_generated_controls.jsonl"))...)
}

func allAccuracySamples(t *testing.T, set string) []labeledAccuracySample {
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
	if set == heldAccuracySet {
		rows = nil
	}
	rows = append(rows, readGeneratedAccuracy[labeledAccuracySample](t, accuracyFixture(set, "testdata/accuracy_generated.jsonl"))...)
	controls := allAccuracyControls(t, set)
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
	for _, set := range selectedAccuracySets(t) {
		t.Run(set, func(t *testing.T) { t.Parallel(); checkAccuracyRegressions(t, set) })
	}
}

func selectedAccuracySets(t *testing.T) []string {
	t.Helper()
	selected := os.Getenv("ACCURACY_SET")
	sets, ok := accuracySets(selected)
	if !ok {
		t.Fatalf("unknown ACCURACY_SET %q: use development or held", selected)
	}
	return sets
}

func accuracySets(selected string) ([]string, bool) {
	switch selected {
	case "":
		return []string{developmentAccuracySet, heldAccuracySet}, true
	case developmentAccuracySet, heldAccuracySet:
		return []string{selected}, true
	default:
		return nil, false
	}
}

func TestAccuracySetSelection(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		selected string
		want     []string
	}{
		{"", []string{developmentAccuracySet, heldAccuracySet}},
		{developmentAccuracySet, []string{developmentAccuracySet}},
		{heldAccuracySet, []string{heldAccuracySet}},
		{"held-out", nil},
		{"development,held", nil},
	} {
		got, valid := accuracySets(tc.selected)
		if !slices.Equal(got, tc.want) || valid != (len(tc.want) > 0) {
			t.Fatalf("selection %q: %v, valid %v", tc.selected, got, valid)
		}
	}
}

func checkAccuracyRegressions(t *testing.T, set string) {
	t.Helper()
	limits := readGeneratedAccuracy[accuracyLimit](t, accuracyFixture(set, "testdata/accuracy_limits.jsonl"))
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
	scanners := map[embargo.Kind]*embargo.Scanner{}
	seen := map[string]bool{}
	for _, sample := range allAccuracySamples(t, set) {
		seen[sample.ID] = true
		findings := accuracyScanner(scanners, sample.Kind, 0).ScanString(sample.Text)
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

func accuracyFixture(set, path string) string {
	if set == heldAccuracySet {
		return strings.Replace(path, "accuracy_", "accuracy_held_", 1)
	}
	return path
}

//nolint:gocognit // Keep exact scoring and negative category reporting in one audit.
func TestCredentialAccuracy(t *testing.T) {
	t.Parallel()
	sets := []string{"development", "held"}
	if selected := os.Getenv("CREDENTIAL_SET"); selected != "" {
		if !slices.Contains(sets, selected) {
			t.Fatal("invalid credential set")
		}
		sets = []string{selected}
	}
	var table strings.Builder
	writeComparisonTable(t, &table, "| Set | Detector | Threshold | TP | FP | FN | Precision | Recall |\n|---|---|---:|---:|---:|---:|---:|---:|\n")
	for _, set := range sets {
		// #nosec G304 G703 -- Set is validated against development/held above.
		data, err := os.ReadFile("testdata/credentials-" + set + ".jsonl")
		if err != nil {
			t.Fatal(err)
		}
		for _, threshold := range []float64{0, 0.5} {
			scanners := map[embargo.Kind]*embargo.Scanner{}
			counts := map[embargo.Kind]accuracyCount{}
			negative := map[string][2]int{}
			lines := bufio.NewScanner(strings.NewReader(string(data)))
			for lines.Scan() {
				var sample struct {
					ID       string         `json:"id"`
					Kind     embargo.Kind   `json:"kind"`
					Group    string         `json:"group"`
					Text     string         `json:"text"`
					Expected []accuracySpan `json:"expected"`
				}
				if err := json.Unmarshal(lines.Bytes(), &sample); err != nil {
					t.Fatal(err)
				}
				findings := accuracyScanner(scanners, sample.Kind, threshold).ScanString(sample.Text)
				result := scoreAccuracy(sample.Kind, findings, sample.Expected)
				count := counts[sample.Kind]
				count.tp += result.tp
				count.fp += result.fp
				count.fn += result.fn
				counts[sample.Kind] = count
				if len(sample.Expected) == 0 {
					key := string(sample.Kind) + "/" + sample.Group
					c := negative[key]
					c[0]++
					if len(findings) > 0 {
						c[1]++
					}
					negative[key] = c
				}
			}
			if err := lines.Err(); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []embargo.Kind{embargo.KindCredential, embargo.KindServiceToken, embargo.KindHighEntropy} {
				c := counts[kind]
				writeComparisonTable(t, &table, "| %s | %s | %.1f | %d | %d | %d | %s | %s |\n", set, kind, threshold, c.tp, c.fp, c.fn, accuracyRatio(c.tp, c.tp+c.fp), accuracyRatio(c.tp, c.tp+c.fn))
			}
			keys := make([]string, 0, len(negative))
			for key := range negative {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			for _, key := range keys {
				n := negative[key]
				t.Logf("%s %.1f %s false positives %d/%d", set, threshold, key, n[1], n[0])
			}
		}
	}
	if len(sets) == 2 {
		syncDocTable(t, "../doc/credentials-accuracy.md", "credentials", table.String())
	} else {
		t.Log(table.String())
	}
}

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

// Each measured kind is evaluated alone against its existing exact-span
// labels; the byte denominator counts these per-kind evaluations, including
// repeated controls. Default reports whether the shipped NewScanner reports
// the kind, observed on the kind's own positives rather than restated.
type defaultThresholdResult struct {
	Set       string       `json:"set"`
	Kind      embargo.Kind `json:"kind"`
	Threshold float64      `json:"threshold"`
	Bytes     int          `json:"bytes"`
	TP        int          `json:"tp"`
	FP        int          `json:"fp"`
	FN        int          `json:"fn"`
	Default   bool         `json:"default"`
}

func TestDefaultThresholdAccuracy(t *testing.T) {
	t.Parallel()
	// Capacity only; the measured kinds come from the labeled samples.
	const sets, thresholds, kindsHint = 2, 3, 32
	results := make([]defaultThresholdResult, 0, sets*thresholds*kindsHint)
	shipped := embargo.NewScanner()
	for _, set := range []string{developmentAccuracySet, heldAccuracySet} {
		samples := allAccuracySamples(t, set)
		samples = append(samples, readGeneratedAccuracy[labeledAccuracySample](t, "testdata/credentials-"+set+".jsonl")...)
		enabled := map[embargo.Kind]bool{}
		for _, sample := range samples {
			if len(sample.Expected) > 0 && slices.ContainsFunc(shipped.ScanString(sample.Text), func(f embargo.Finding) bool { return f.Kind == sample.Kind }) {
				enabled[sample.Kind] = true
			}
		}
		for _, threshold := range []float64{0, .5, .7} {
			counts := map[embargo.Kind]defaultThresholdResult{}
			scanners := map[embargo.Kind]*embargo.Scanner{}
			for _, sample := range samples {
				if sample.Kind == embargo.KindHighEntropy {
					continue
				}
				score := scoreAccuracy(sample.Kind, accuracyScanner(scanners, sample.Kind, threshold).ScanString(sample.Text), sample.Expected)
				count := counts[sample.Kind]
				count.Set = set
				count.Kind = sample.Kind
				count.Threshold = threshold
				count.Bytes += len(sample.Text)
				count.TP += score.tp
				count.FP += score.fp
				count.FN += score.fn
				count.Default = enabled[sample.Kind]
				counts[sample.Kind] = count
			}
			if len(counts) == 0 || len(enabled) == 0 {
				t.Fatal("no measured or shipped kinds")
			}
			names := make([]string, 0, len(counts))
			for kind := range counts {
				names = append(names, string(kind))
			}
			slices.Sort(names)
			for _, kind := range names {
				results = append(results, counts[embargo.Kind(kind)])
			}
		}
	}
	syncSeverityJSON(t, "../doc/default-thresholds.json", results)
}
