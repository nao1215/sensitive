package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
		Benchmarks map[string]map[string]float64 `json:"benchmarks"`
		Date       string                        `json:"date"`
		GoVersion  string                        `json:"go_version"`
		OS         string                        `json:"os"`
		Arch       string                        `json:"arch"`
		CPU        string                        `json:"cpu"`
		Commit     string                        `json:"commit"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	var table strings.Builder
	printLine := func(format string, args ...any) {
		if _, err := fmt.Fprintf(&table, format, args...); err != nil {
			t.Fatal(err)
		}
	}
	printLine("Measured %s with %s, %s/%s, %s, GOMAXPROCS=1; median of five 200 ms samples at [%s](https://github.com/nao1215/embargo/commit/%s).\n\n", snapshot.Date, snapshot.GoVersion, snapshot.OS, snapshot.Arch, snapshot.CPU, snapshot.Commit[:7], snapshot.Commit)
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
	syncReadmeTable(t, "benchmarks", table.String())
}
