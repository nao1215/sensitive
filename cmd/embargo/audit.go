package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
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
const (
	auditName  = "embargo audit"
	auditUsage = "Usage: embargo audit [--kinds email,pan] [--all] [--min-confidence 0] [--samples 3] [--compare] [--compare-kinds email] [--compare-all] [--compare-min-confidence 0] [file ...]\n\nReports per-kind finding counts and masked byte locations as JSON; input bytes are never echoed.\n"
)

type report struct {
	Findings []kindReport `json:"findings"`
	Bytes    int64        `json:"bytes"`
	Lines    int          `json:"lines"`
}

// runAudit reports per-kind counts and masked locations instead of masked lines.
func runAudit(args []string, input io.Reader, output io.Writer) error {
	options, files, err := parseAuditOptions(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return writeUsage(output, auditUsage)
		}
		return err
	}

	scanner, err := selectedScanner(options.kinds, options.all, options.minimum, auditName+": --kinds")
	if err != nil {
		return err
	}
	input, closeInputs := openInputs(files, input)
	defer closeInputs()
	var result any
	if options.compare {
		second, selectErr := selectedScanner(options.compareKinds, options.compareAll, options.compareMinimum, auditName+": --compare-kinds")
		if selectErr != nil {
			return selectErr
		}
		result, err = auditPair(input, scanner, second, options.samples)
	} else {
		result, err = audit(input, scanner, options.samples)
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
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
		return comparisonReport{}, errors.New(auditName + ": input read failed or line reached the 4 MiB limit")
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

// auditOptions separates flag decoding and validation from scanning and encoding.
type auditOptions struct {
	kinds, compareKinds, minimumText, compareMinimumText, samplesText string
	all, compare, compareAll                                          bool
	minimum, compareMinimum                                           float64
	samples                                                           int
}

func parseAuditOptions(args []string) (*auditOptions, []string, error) {
	options := &auditOptions{}
	flags := flag.NewFlagSet(auditName, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.kinds, "kinds", "", "comma-separated kinds; default scanner if omitted")
	flags.BoolVar(&options.all, "all", false, "include opt-in country and entropy kinds")
	flags.BoolVar(&options.compare, "compare", false, "compare the base and second settings on the same input")
	flags.StringVar(&options.compareKinds, "compare-kinds", "", "second comma-separated kind set")
	flags.BoolVar(&options.compareAll, "compare-all", false, "include every kind in the second setting")
	flags.StringVar(&options.compareMinimumText, "compare-min-confidence", "0", "second inclusive minimum confidence")
	flags.StringVar(&options.minimumText, "min-confidence", "0", "inclusive minimum detector confidence")
	const defaultSamples = "3"
	flags.StringVar(&options.samplesText, "samples", defaultSamples, "maximum masked locations per kind (0 through 20)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil, err
		}
		return nil, nil, errors.New(auditName + ": invalid flags\nUsage: embargo audit [--kinds email,pan] [--all] [--compare] [file ...]; use --help for options")
	}
	if err := options.validate(flags); err != nil {
		return nil, nil, err
	}
	return options, flags.Args(), nil
}

func (options *auditOptions) validate(flags *flag.FlagSet) error {
	const maximumSamples = 20
	minimum, validMinimum := parseConfidence(options.minimumText)
	if !validMinimum {
		return errors.New(auditName + ": --min-confidence must be between 0 and 1")
	}
	samples, sampleErr := strconv.Atoi(options.samplesText)
	if sampleErr != nil || samples < 0 || samples > maximumSamples {
		return errors.New(auditName + ": --samples must be between 0 and 20")
	}
	compareMinimum, validCompare := parseConfidence(options.compareMinimumText)
	if !validCompare {
		return errors.New(auditName + ": --compare-min-confidence must be between 0 and 1")
	}
	if options.all && options.kinds != "" {
		return errors.New(auditName + ": --all and --kinds cannot be combined")
	}
	if options.compareAll && options.compareKinds != "" {
		return errors.New(auditName + ": --compare-all and --compare-kinds cannot be combined")
	}

	invalidCompare := false
	flags.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "compare-") && !options.compare {
			invalidCompare = true
		}
	})
	if invalidCompare {
		return errors.New(auditName + ": comparison flags require --compare")
	}
	options.minimum, options.compareMinimum, options.samples = minimum, compareMinimum, samples
	return nil
}
