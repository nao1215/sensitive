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
		CoveredStatements          int     `json:"covered_statements"`
		TotalStatements            int     `json:"total_statements"`
		Efficacy                   float64 `json:"efficacy"`
		MutatorCoverage            float64 `json:"mutator_coverage"`
		MutationTimeoutCoefficient int     `json:"mutation_timeout_coefficient"`
		MutationWorkers            int     `json:"mutation_workers"`
		Mutation                   struct {
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
	text := fmt.Sprintf("Measured %s at [%s](https://github.com/nao1215/embargo/commit/%s).\n\n| Measurement | Result | Conditions |\n|---|---|---|\n| Statement coverage | %.1f%% (%d/%d) | Root and integration suites combined |\n| Mutation score | %.2f%% | gremlins v0.6.0, root tests, %d workers, %dx timeout |\n| Mutations | %d killed, %d lived, %d uncovered, %d timed out | Timeouts do not count as killed |\n| Mutation coverage | %.2f%% | Mutated statements exercised by root tests |\n| Fuzzing | %d targets, %d executions | 10 seconds per target |\n", snapshot.Date, snapshot.Commit[:7], snapshot.Commit, 100*float64(snapshot.CoveredStatements)/float64(snapshot.TotalStatements), snapshot.CoveredStatements, snapshot.TotalStatements, snapshot.Efficacy, snapshot.MutationWorkers, snapshot.MutationTimeoutCoefficient, snapshot.Mutation.Killed, snapshot.Mutation.Lived, snapshot.Mutation.Uncovered, snapshot.Mutation.TimedOut, snapshot.MutatorCoverage, len(snapshot.Fuzz), executions)
	syncDocTable(t, "../doc/testing.md", "testing-metrics", text)
	summary := fmt.Sprintf("Coverage %.1f%% · mutation score %.2f%% · %d fuzz targets, %d executions.\n", 100*float64(snapshot.CoveredStatements)/float64(snapshot.TotalStatements), snapshot.Efficacy, len(snapshot.Fuzz), executions)
	syncReadmeTable(t, "testing-metrics", summary)
}
