package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strings"

	"github.com/nao1215/embargo"
)

type location struct {
	Value  string `json:"value"`
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}
type kindReport struct {
	Kind       embargo.Kind `json:"kind"`
	DropOption string       `json:"drop_option"`
	Samples    []location   `json:"samples"`
	Count      int64        `json:"count"`
}
type report struct {
	Findings []kindReport `json:"findings"`
	Bytes    int64        `json:"bytes"`
	Lines    int          `json:"lines"`
}

func main() { os.Exit(exitCode(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func exitCode(args []string, input io.Reader, output, diagnostics io.Writer) int {
	if err := run(args, input, output); err != nil {
		// The failure status is already set; a diagnostic write cannot make it succeed.
		if _, writeErr := fmt.Fprintln(diagnostics, err); writeErr != nil {
			return 1
		}
		return 1
	}
	return 0
}

func run(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("embargo-audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kinds := flags.String("kinds", "", "comma-separated kinds; default scanner if omitted")
	all := flags.Bool("all", false, "include opt-in country and entropy kinds")
	compare := flags.Bool("compare", false, "compare the base and second settings on the same input")
	compareKinds := flags.String("compare-kinds", "", "second comma-separated kind set")
	compareAll := flags.Bool("compare-all", false, "include every kind in the second setting")
	compareMinimum := flags.Float64("compare-min-confidence", 0, "second inclusive minimum confidence")
	minimum := flags.Float64("min-confidence", 0, "inclusive minimum detector confidence")
	const defaultSamples = 3
	const maximumSamples = 20
	samples := flags.Int("samples", defaultSamples, "maximum masked locations per kind (0 through 20)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, writeErr := io.WriteString(output, "Usage: embargo-audit [--kinds email,pan] [--all] [--min-confidence 0] [--samples 3] [--compare] [--compare-kinds email] [--compare-all] [--compare-min-confidence 0] < input\n")
			return writeErr
		}
		return errors.New("embargo-audit: invalid flags\nUsage: embargo-audit [--kinds email,pan] [--all] [--compare] < input; use --help for options")
	}
	if flags.NArg() != 0 || *samples < 0 || *samples > maximumSamples || (*all && *kinds != "") || math.IsNaN(*minimum) || *minimum < 0 || *minimum > 1 {
		return errors.New("embargo-audit: invalid selection, confidence or sample limit")
	}
	if math.IsNaN(*compareMinimum) || *compareMinimum < 0 || *compareMinimum > 1 || (*compareAll && *compareKinds != "") {
		return errors.New("embargo-audit: invalid comparison settings")
	}
	invalidCompare := false
	flags.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "compare-") && !*compare {
			invalidCompare = true
		}
	})
	if invalidCompare {
		return errors.New("embargo-audit: comparison flags require --compare")
	}
	scanner, err := selectedScanner(*kinds, *all, *minimum)
	if err != nil {
		return err
	}
	var result any
	if *compare {
		second, selectErr := selectedScanner(*compareKinds, *compareAll, *compareMinimum)
		if selectErr != nil {
			return selectErr
		}
		result, err = auditPair(input, scanner, second, *samples)
	} else {
		result, err = audit(input, scanner, *samples)
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func selectedScanner(kinds string, all bool, minimum float64) (scanner *embargo.Scanner, err error) {
	// WithKinds rejects unknown public Kind strings; convert only this input error
	// to a fixed diagnostic instead of echoing possibly sensitive arguments.
	defer func() {
		if recover() != nil {
			scanner = nil
			err = errors.New("embargo-audit: unknown kind")
		}
	}()
	options := []embargo.ScannerOption{embargo.WithMinConfidence(minimum)}
	if all {
		options = append(options, embargo.WithAll())
	}
	if kinds != "" {
		selection := make([]embargo.Kind, 0, strings.Count(kinds, ",")+1)
		for kind := range strings.SplitSeq(kinds, ",") {
			selection = append(selection, embargo.Kind(strings.TrimSpace(kind)))
		}
		options = append(options, embargo.WithKinds(selection...))
	}
	return embargo.NewScanner(options...), nil
}

type comparisonReport struct {
	Gained []kindReport `json:"gained"`
	Lost   []kindReport `json:"lost"`
	Before report       `json:"before"`
	After  report       `json:"after"`
}

func audit(input io.Reader, scanner *embargo.Scanner, sampleLimit int) (report, error) {
	result, err := auditPair(input, scanner, nil, sampleLimit)
	return result.Before, err
}

// Both settings see each line before it is discarded, so comparisons use bounded memory.
func auditPair(input io.Reader, first, second *embargo.Scanner, sampleLimit int) (comparisonReport, error) {
	groups := [4]map[embargo.Kind]*kindReport{}
	for i := range groups {
		groups[i] = make(map[embargo.Kind]*kindReport)
	}
	lines := bufio.NewScanner(input)
	const maximumLine = 4 << 20
	lines.Buffer(make([]byte, bufio.MaxScanTokenSize), maximumLine)
	var bytesRead, lineStart int64
	lineCount := 0
	lines.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		advance, token, err = bufio.ScanLines(data, atEOF)
		if advance > 0 {
			lineStart = bytesRead
			bytesRead += int64(advance)
		}
		return advance, token, err
	})
	for lines.Scan() {
		lineCount++
		before := first.Scan(lines.Bytes())
		var after []embargo.Finding
		if second != nil {
			after = second.Scan(lines.Bytes())
		}
		batches := [4][]embargo.Finding{before, after, findingDifference(after, before), findingDifference(before, after)}
		for i, findings := range batches {
			for _, finding := range findings {
				addFinding(groups[i], finding, lineStart, lineCount, sampleLimit)
			}
		}
	}
	if lines.Err() != nil {
		return comparisonReport{}, errors.New("embargo-audit: input read failed or line reached the 4 MiB limit")
	}
	return comparisonReport{
		Before: report{Findings: sortedKinds(groups[0]), Bytes: bytesRead, Lines: lineCount},
		After:  report{Findings: sortedKinds(groups[1]), Bytes: bytesRead, Lines: lineCount},
		Gained: sortedKinds(groups[2]), Lost: sortedKinds(groups[3]),
	}, nil
}

func findingDifference(left, right []embargo.Finding) []embargo.Finding {
	type identity struct {
		kind       embargo.Kind
		start, end int
	}
	present := make(map[identity]bool, len(right))
	for _, f := range right {
		present[identity{f.Kind, f.Start, f.End}] = true
	}
	result := make([]embargo.Finding, 0)
	for _, f := range left {
		if !present[identity{f.Kind, f.Start, f.End}] {
			result = append(result, f)
		}
	}
	return result
}

func addFinding(groups map[embargo.Kind]*kindReport, finding embargo.Finding, lineStart int64, line, sampleLimit int) {
	group := groups[finding.Kind]
	if group == nil {
		group = &kindReport{Kind: finding.Kind, DropOption: fmt.Sprintf("Use embargo.WithKinds with required kinds, omitting embargo.Kind(%q).", finding.Kind), Samples: []location{}}
		groups[finding.Kind] = group
	}
	group.Count++
	if len(group.Samples) < sampleLimit {
		group.Samples = append(group.Samples, location{Value: "[REDACTED]", Start: lineStart + int64(finding.Start), End: lineStart + int64(finding.End), Line: line, Column: finding.Start})
	}
}

func sortedKinds(groups map[embargo.Kind]*kindReport) []kindReport {
	kinds := make([]embargo.Kind, 0, len(groups))
	for kind := range groups {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	result := make([]kindReport, 0, len(groups))
	for _, kind := range kinds {
		result = append(result, *groups[kind])
	}
	return result
}
