package tests

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

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
