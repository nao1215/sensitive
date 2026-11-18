package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestBenchmarkTable(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../doc/benchmarks.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		BackgroundLoad string                        `json:"background_load"`
		Benchmarks     map[string]map[string]float64 `json:"benchmarks"`
		Date           string                        `json:"date"`
		GoVersion      string                        `json:"go_version"`
		OS             string                        `json:"os"`
		Arch           string                        `json:"arch"`
		CPU            string                        `json:"cpu"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	checkBenchmarkSamples(t, snapshot.Benchmarks)
	var table strings.Builder
	printLine := func(format string, args ...any) {
		if _, err := fmt.Fprintf(&table, format, args...); err != nil {
			t.Fatal(err)
		}
	}
	printLine("Measured %s with %s, %s/%s, %s, GOMAXPROCS=1; median of ten 200 ms samples.\n\n", snapshot.Date, snapshot.GoVersion, snapshot.OS, snapshot.Arch, snapshot.CPU)
	printLine("Background load: %s.\n\n", snapshot.BackgroundLoad)
	printLine("| Operation | ns/op | MB/s | B/op | allocs/op |\n|---|---:|---:|---:|---:|\n")
	for _, row := range []struct{ label, name string }{
		{label: "Scanner WithAll, clean", name: "Scanner/all/clean"},
		{label: "Scanner WithAll, dirty", name: "Scanner/all/dirty"},
		{label: "Mask", name: "Mask"},
		{label: "Writer only", name: "Recorder/plain"},
		{label: "Recorder + Check", name: "Recorder/checked"},
		{label: "Plain slog, clean", name: "Slog/plain-clean"},
		{label: "Masked slog, clean", name: "Slog/masked-clean"},
		{label: "Plain slog, dirty", name: "Slog/plain-dirty"},
		{label: "Masked slog, dirty", name: "Slog/masked-dirty"},
	} {
		values, ok := snapshot.Benchmarks["BenchmarkPublished"+row.name]
		if !ok {
			t.Fatal("benchmark missing")
		}
		throughput := "—"
		if value, ok := values["MB/s"]; ok {
			throughput = fmt.Sprintf("%.2f", value)
		}
		printLine("| %s | %.1f | %s | %.0f | %.0f |\n", row.label, values["ns/op"], throughput, values["B/op"], values["allocs/op"])
	}
	printLine("\nParallel: ns/op is wall time per event across all goroutines.\n\n")
	printLine("| Shared value | ")
	procsList := parallelProcs()
	for _, procs := range procsList {
		printLine("%d CPU ns/op | ", procs)
	}
	printLine("%d CPU vs 1 CPU |\n|---|%s---:|\n", procsList[len(procsList)-1], strings.Repeat("---:|", len(procsList)))
	for _, row := range []struct{ label, name string }{
		{label: "Scanner.Scan", name: parallelScanner},
		{label: "slog handler", name: loggerSlog},
		{label: "zap WriteSyncer", name: loggerZap},
	} {
		var first, last float64
		printLine("| %s | ", row.label)
		for index, procs := range procsList {
			values, ok := snapshot.Benchmarks[fmt.Sprintf("BenchmarkPublishedParallel/%s/%dprocs", row.name, procs)]
			if !ok {
				t.Fatal("parallel benchmark missing")
			}
			if index == 0 {
				first = values["ns/op"]
			}
			last = values["ns/op"]
			printLine("%.1f | ", values["ns/op"])
		}
		printLine("%s |\n", speedFactor(first, last))
	}
	printLine("\n<details>\n<summary>Per-detector Scanner throughput</summary>\n\n| Detector | Clean MB/s | Dirty MB/s |\n|---|---:|---:|\n")
	var names []string
	for name := range snapshot.Benchmarks {
		if strings.HasPrefix(name, "BenchmarkPublishedScanner/") && strings.HasSuffix(name, "/clean") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(name, "BenchmarkPublishedScanner/"), "/clean"))
		}
	}
	sort.Strings(names)
	for _, name := range names {
		prefix := "BenchmarkPublishedScanner/" + name
		printLine("| %s | %.2f | %.2f |\n", name, snapshot.Benchmarks[prefix+"/clean"]["MB/s"], snapshot.Benchmarks[prefix+"/dirty"]["MB/s"])
	}
	printLine("\n</details>\n")
	syncDocTable(t, "../doc/benchmarks.md", "benchmarks", table.String())
	summary := "![Time per log event](doc/images/log-event-time.svg)\n\nThe same event through slog alone, embargo with the email and card rules masq and go-masker are given, embargo's default scanner against pii-shield's default policy, masq and go-masker. [Configurations, medians and allocations](doc/comparison.md) · [Full scanner benchmark plot](doc/benchmarks.md).\n"
	syncReadmeTable(t, "benchmarks", summary)
}

// speedFactor states how much faster the after time is than before, with a
// factor of one or more: "1.4x faster", "1.1x slower" or "same" within 5%.
func speedFactor(before, after float64) string {
	const tolerance = 1.05
	switch {
	case before >= after*tolerance:
		return fmt.Sprintf("%.1fx faster", before/after)
	case after >= before*tolerance:
		return fmt.Sprintf("%.1fx slower", after/before)
	default:
		return "same"
	}
}

func checkBenchmarkSamples(t *testing.T, medians map[string]map[string]float64) {
	t.Helper()
	raw, err := os.ReadFile("../doc/benchmarks.raw.txt")
	if err != nil {
		t.Fatal(err)
	}
	samples := map[string]map[string][]float64{}
	cpuSuffix := regexp.MustCompile(`-\d+$`)
	for line := range strings.SplitSeq(string(raw), "\n") {
		if !strings.HasPrefix(line, "BenchmarkPublished") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || len(fields)%2 != 0 { // Name, iterations, then value/unit pairs.
			t.Fatal("invalid benchmark sample")
		}
		name := cpuSuffix.ReplaceAllString(fields[0], "")
		if samples[name] == nil {
			samples[name] = map[string][]float64{}
		}
		for index := 2; index < len(fields); index += 2 {
			value, err := strconv.ParseFloat(fields[index], 64)
			if err != nil {
				t.Fatal(err)
			}
			unit := fields[index+1]
			samples[name][unit] = append(samples[name][unit], value)
		}
	}
	if len(samples) != len(medians) {
		t.Fatal("benchmark case count differs from raw output")
	}
	for name, metrics := range samples {
		if len(metrics) != len(medians[name]) {
			t.Fatal("benchmark metric count differs from raw output")
		}
		for unit, values := range metrics {
			if len(values) != 10 { // Publication requires ten independent timing samples.
				t.Fatal("benchmark sample count differs from publication protocol")
			}
			slices.Sort(values)
			median := (values[len(values)/2-1] + values[len(values)/2]) / 2
			if value, ok := medians[name][unit]; !ok || value != median {
				t.Fatal("benchmark median differs from raw output")
			}
		}
	}
}

func TestTestingMetrics(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../doc/testing-metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Date string `json:"date"`
		Fuzz []struct {
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
	if snapshot.TotalStatements <= 0 || snapshot.CoveredStatements > snapshot.TotalStatements {
		t.Fatal("invalid measurement provenance")
	}
	executions := 0
	for _, run := range snapshot.Fuzz {
		executions += run.Executions
		if run.SecondsRequested != 10 || run.Target == "" || run.Executions <= 0 {
			t.Fatal("invalid fuzz measurement")
		}
	}
	text := fmt.Sprintf("Measured %s; retained snapshot with source-log hashes.\n\n| Measurement | Result | Conditions |\n|---|---|---|\n| Statement coverage | %.1f%% (%d/%d) | Root and integration suites combined |\n| Mutation score | %.2f%% | gremlins v0.6.0, root tests, %d workers, %dx timeout |\n| Mutations | %d killed, %d lived, %d uncovered, %d timed out | Timeouts do not count as killed |\n| Mutation coverage | %.2f%% | Mutated statements exercised by root tests |\n| Fuzzing | %d targets, %d executions | 10 seconds per target |\n", snapshot.Date, 100*float64(snapshot.CoveredStatements)/float64(snapshot.TotalStatements), snapshot.CoveredStatements, snapshot.TotalStatements, snapshot.Efficacy, snapshot.MutationWorkers, snapshot.MutationTimeoutCoefficient, snapshot.Mutation.Killed, snapshot.Mutation.Lived, snapshot.Mutation.Uncovered, snapshot.Mutation.TimedOut, snapshot.MutatorCoverage, len(snapshot.Fuzz), executions)
	syncDocTable(t, "../doc/testing.md", "testing-metrics", text)
	summary := fmt.Sprintf("Coverage %.1f%% · mutation score %.2f%% · %d fuzz targets, %d executions.\n", 100*float64(snapshot.CoveredStatements)/float64(snapshot.TotalStatements), snapshot.Efficacy, len(snapshot.Fuzz), executions)
	syncReadmeTable(t, "testing-metrics", summary)
}
