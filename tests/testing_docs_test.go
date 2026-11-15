package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestTestingMetrics(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../doc/testing-metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Date   string `json:"date"`
		Commit string `json:"commit"`
		Fuzz   []struct {
			Target           string `json:"target"`
			Executions       int    `json:"executions"`
			SecondsRequested int    `json:"seconds_requested"`
		} `json:"fuzz"`
		CoveredStatements int     `json:"covered_statements"`
		TotalStatements   int     `json:"total_statements"`
		Efficacy          float64 `json:"efficacy"`
		MutatorCoverage   float64 `json:"mutator_coverage"`
		Mutation          struct {
			Killed    int `json:"killed"`
			Lived     int `json:"lived"`
			Uncovered int `json:"uncovered"`
			TimedOut  int `json:"timed_out"`
		} `json:"mutation"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.TotalStatements <= 0 || snapshot.CoveredStatements > snapshot.TotalStatements || len(snapshot.Commit) != 40 {
		t.Fatal("invalid measurement provenance")
	}
	executions := 0
	for _, run := range snapshot.Fuzz {
		executions += run.Executions
		if run.SecondsRequested != 10 || run.Target == "" || run.Executions <= 0 {
			t.Fatal("invalid fuzz measurement")
		}
	}
	text := fmt.Sprintf("Measured %s at [%s](https://github.com/nao1215/embargo/commit/%s): %.1f%% statement coverage (%d/%d, root and integration suites combined); gremlins v0.6.0 efficacy %.2f%% (%d killed, %d lived, %d uncovered, %d timed out; mutator coverage %.2f%%); %d fuzz targets at 10 seconds each, %d executions. Timeouts are reported separately and do not count as killed. These are dated measurements, not guarantees for arbitrary inputs.\n", snapshot.Date, snapshot.Commit[:7], snapshot.Commit, 100*float64(snapshot.CoveredStatements)/float64(snapshot.TotalStatements), snapshot.CoveredStatements, snapshot.TotalStatements, snapshot.Efficacy, snapshot.Mutation.Killed, snapshot.Mutation.Lived, snapshot.Mutation.Uncovered, snapshot.Mutation.TimedOut, snapshot.MutatorCoverage, len(snapshot.Fuzz), executions)
	syncReadmeTable(t, "testing-metrics", text)
}
