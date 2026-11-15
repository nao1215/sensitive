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
		Commit         string                        `json:"commit"`
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
	printLine("Measured %s with %s, %s/%s, %s, GOMAXPROCS=1; median of five 200 ms samples at [%s](https://github.com/nao1215/embargo/commit/%s).\n\n", snapshot.Date, snapshot.GoVersion, snapshot.OS, snapshot.Arch, snapshot.CPU, snapshot.Commit[:7], snapshot.Commit)
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
	all := snapshot.Benchmarks["BenchmarkPublishedScanner/all/dirty"]["MB/s"]
	plain := snapshot.Benchmarks["BenchmarkPublishedSlog/plain-clean"]["ns/op"]
	masked := snapshot.Benchmarks["BenchmarkPublishedSlog/masked-clean"]["ns/op"]
	summary := fmt.Sprintf("![Scanner throughput and slog time](doc/images/benchmarks.svg)\n\nAll detectors scan sensitive text at %.2f MB/s; masking a clean slog event takes %.2f µs, %.1f× the plain handler.\n", all, masked/1000, masked/plain)
	syncReadmeTable(t, "benchmarks", summary)
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
			if len(values) != 5 { // Publication requires five independent timing samples.
				t.Fatal("benchmark sample count differs from publication protocol")
			}
			slices.Sort(values)
			if value, ok := medians[name][unit]; !ok || value != values[len(values)/2] {
				t.Fatal("benchmark median differs from raw output")
			}
		}
	}
}
