package sensitive_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/nao1215/sensitive"
)

// TestLabeledRecall measures individual detectors, avoiding overlap suppression
// by WithAll. Every positive must be found and every negative must be rejected.
func TestLabeledRecall(t *testing.T) {
	data, err := os.ReadFile("testdata/recall.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Detector string   `json:"detector"`
		Text     string   `json:"text"`
		Parts    []string `json:"parts"`
		Positive bool     `json:"positive"`
	}
	if err = json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	known := make(map[string]bool)
	for _, d := range builtinDetectors() {
		name := string(d.Name())
		known[name] = true
		t.Run(name, func(t *testing.T) {
			s := sensitive.NewScanner(sensitive.WithDetector(d))
			pos, neg, tp, fp := 0, 0, 0, 0
			for _, r := range rows {
				if r.Detector != name {
					continue
				}
				text := r.Text + strings.Join(r.Parts, "")
				found := len(s.ScanString(text)) > 0
				if r.Positive {
					pos++
					if found {
						tp++
					}
				} else {
					neg++
					if found {
						fp++
					}
				}
				if found != r.Positive {
					t.Errorf("label=%v text=%q found=%v", r.Positive, text, found)
				}
			}
			if pos == 0 || neg == 0 {
				t.Fatal("missing corpus stratum")
			}
			t.Logf("recall=%d/%d false_positives=%d/%d", tp, pos, fp, neg)
		})
	}
	for _, r := range rows {
		if !known[r.Detector] {
			t.Errorf("unknown detector %q", r.Detector)
		}
	}
}
