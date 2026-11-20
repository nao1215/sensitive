package tests

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
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
	summary := "![Time per log event](doc/images/log-event-time.svg)\n\n[Configurations, medians and allocations](doc/comparison.md) · [Full scanner benchmark plot](doc/benchmarks.md).\n"
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

// The website is checked against the repository it documents: every page
// is in the menu, every link to a page, a heading or a repository file
// resolves, every block it shares with the README or doc/ is identical,
// and every link from Go documentation or Markdown to the site lands on a
// heading, as every link to a file on the main branch names a file.
// Code blocks and command lines are checked by the root module's doc tests.

const siteURL = "https://nao1215.github.io/embargo/"

// sitePages maps a page path such as "/kinds/" to its Markdown.
func sitePages(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("../website/content/*.md")
	if err != nil || len(files) == 0 {
		t.Fatal("website pages not found")
	}
	pages := map[string]string{}
	for _, file := range files {
		// #nosec G304 -- The paths are repository documentation files.
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(filepath.Base(file), ".md")
		path := "/" + name + "/"
		if name == "_index" {
			path = "/"
		}
		pages[path] = strings.ReplaceAll(string(data), "\r\n", "\n")
	}
	return pages
}

// headingAnchor is the id Hugo gives a Markdown heading by default: lower
// case, punctuation other than - and _ removed, spaces turned into -.
func headingAnchor(heading string) string {
	anchor := make([]rune, 0, len(heading))
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			anchor = append(anchor, '-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			anchor = append(anchor, r)
		}
	}
	return string(anchor)
}

// pageAnchors returns the heading ids of a page, outside code blocks.
func pageAnchors(markdown string) map[string]bool {
	anchors := map[string]bool{}
	fence := false
	for line := range strings.SplitSeq(markdown, "\n") {
		if strings.HasPrefix(line, "```") {
			fence = !fence
		}
		if heading, ok := strings.CutPrefix(strings.TrimLeft(line, "#"), " "); ok && !fence && strings.HasPrefix(line, "##") {
			anchors[headingAnchor(heading)] = true
		}
	}
	return anchors
}

// checkSiteLink reports why a link to a page of the site does not resolve.
func checkSiteLink(pages map[string]string, link string) string {
	path, anchor, _ := strings.Cut(link, "#")
	page, ok := pages[path]
	switch {
	case !ok:
		return "no such page"
	case anchor != "" && !pageAnchors(page)[anchor]:
		return "no such heading"
	}
	return ""
}

func TestSiteMenuListsEveryPage(t *testing.T) {
	t.Parallel()
	config, err := os.ReadFile("../website/hugo.toml")
	if err != nil {
		t.Fatal(err)
	}
	menu := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?m)^pageRef = "(/[a-z-]+)"$`).FindAllStringSubmatch(string(config), -1) {
		menu[match[1]+"/"] = true
	}
	for path := range sitePages(t) {
		if path != "/" && !menu[path] {
			t.Errorf("%s is not in the menu", path)
		}
		delete(menu, path)
	}
	for path := range menu {
		t.Errorf("the menu names %s, which has no page", path)
	}
}

func TestSiteLinksResolve(t *testing.T) {
	t.Parallel()
	pages := sitePages(t)
	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	for path, page := range pages {
		fence := false
		for line := range strings.SplitSeq(page, "\n") {
			if strings.HasPrefix(line, "```") {
				fence = !fence
			}
			if fence {
				continue
			}
			// Inline code such as `Secret[string]([REDACTED])` holds no links.
			line = regexp.MustCompile("`[^`]*`").ReplaceAllString(line, "")
			for _, match := range link.FindAllStringSubmatch(line, -1) {
				if problem := checkPageLink(pages, path, match[1]); problem != "" {
					t.Errorf("%s links %s: %s", path, match[1], problem)
				}
			}
		}
	}
}

// checkPageLink resolves one link written on a page the way the site's
// render hooks do.
func checkPageLink(pages map[string]string, page, link string) string {
	switch {
	case strings.HasPrefix(link, siteURL):
		return checkSiteLink(pages, "/"+strings.TrimPrefix(link, siteURL))
	case strings.HasPrefix(link, "/"):
		return checkSiteLink(pages, link)
	case strings.HasPrefix(link, "#"):
		return checkSiteLink(pages, page+link)
	case regexp.MustCompile(`^[a-z]+:`).MatchString(link):
		return ""
	}
	file, _, _ := strings.Cut(link, "#")
	if strings.HasPrefix(file, "figures/") {
		file = "website/" + file
	}
	if _, err := fs.Stat(os.DirFS(".."), strings.TrimSuffix(file, "/")); err != nil {
		return "no such repository file"
	}
	return ""
}

func TestDocumentationLinksResolve(t *testing.T) {
	t.Parallel()
	pages := sitePages(t)
	link := regexp.MustCompile(regexp.QuoteMeta(siteURL) + "[^\\s)\\]\"`]*[^\\s)\\].,\"`]")
	blob := regexp.MustCompile(`https://github\.com/nao1215/embargo/blob/main/([A-Za-z0-9_./-]*[A-Za-z0-9_/-])`)
	found := 0
	repository := os.DirFS("..")
	err := fs.WalkDir(repository, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && path != "." && (entry.Name() == "website" || strings.HasPrefix(entry.Name(), ".")) {
			return fs.SkipDir
		}
		if entry.IsDir() || (!strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".md")) {
			return nil
		}
		data, err := fs.ReadFile(repository, path)
		if err != nil {
			return err
		}
		for _, match := range link.FindAllString(string(data), -1) {
			found++
			if problem := checkSiteLink(pages, "/"+strings.TrimPrefix(match, siteURL)); problem != "" {
				t.Errorf("%s links %s: %s", path, match, problem)
			}
		}
		// A link to a file on the main branch breaks when the file moves.
		for _, match := range blob.FindAllStringSubmatch(string(data), -1) {
			if _, err := fs.Stat(repository, strings.TrimSuffix(match[1], "/")); err != nil {
				t.Errorf("%s links %s, which is not in the repository", path, match[0])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no links to the site found")
	}
}

// TestSiteSharesGeneratedBlocks keeps a generated block that a page shows
// identical to the README or doc/ copy its generator writes. Run it with
// UPDATE_DOCS=1 after regenerating the README or doc/ to copy the blocks.
func TestSiteSharesGeneratedBlocks(t *testing.T) {
	t.Parallel()
	sources, err := filepath.Glob("../doc/*.md")
	if err != nil {
		t.Fatal(err)
	}
	sources = append([]string{"../README.md"}, sources...)
	marker := regexp.MustCompile(`<!-- ([a-z-]+):start -->`)
	files, err := filepath.Glob("../website/content/*.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		// #nosec G304 -- The paths are repository documentation files.
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range marker.FindAllStringSubmatch(string(data), -1) {
			for _, source := range sources {
				// #nosec G304 -- The paths are repository documentation files.
				text, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				if block, ok := markedBlock(string(text), match[1]); ok {
					syncDocTable(t, file, match[1], block)
					break
				}
			}
		}
	}
}

// markedBlock returns the text between a block's start and end markers.
func markedBlock(text, name string) (string, bool) {
	_, rest, ok := strings.Cut(text, "<!-- "+name+":start -->\n")
	if !ok {
		return "", false
	}
	block, _, ok := strings.Cut(rest, "<!-- "+name+":end -->")
	return block, ok
}
