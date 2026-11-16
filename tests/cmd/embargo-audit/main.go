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

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, err); writeErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

func run(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("embargo-audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kinds := flags.String("kinds", "", "comma-separated kinds; default scanner if omitted")
	all := flags.Bool("all", false, "include opt-in country and entropy kinds")
	minimum := flags.Float64("min-confidence", 0, "inclusive minimum detector confidence")
	const defaultSamples = 3
	const maximumSamples = 20
	samples := flags.Int("samples", defaultSamples, "maximum masked locations per kind (0 through 20)")
	if err := flags.Parse(args); err != nil {
		return errors.New("embargo-audit: invalid flags; see doc/audit.md")
	}
	if flags.NArg() != 0 || *samples < 0 || *samples > maximumSamples || (*all && *kinds != "") || math.IsNaN(*minimum) || *minimum < 0 || *minimum > 1 {
		return errors.New("embargo-audit: invalid selection, confidence or sample limit")
	}
	scanner, err := selectedScanner(*kinds, *all, *minimum)
	if err != nil {
		return err
	}
	result, err := audit(input, scanner, *samples)
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

func audit(input io.Reader, scanner *embargo.Scanner, sampleLimit int) (report, error) {
	result := report{Findings: []kindReport{}}
	byKind := map[embargo.Kind]*kindReport{}
	lines := bufio.NewScanner(input)
	const maximumLine = 4 << 20
	lines.Buffer(make([]byte, bufio.MaxScanTokenSize), maximumLine)
	var lineStart int64
	lines.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		advance, token, err = bufio.ScanLines(data, atEOF)
		if advance > 0 {
			lineStart = result.Bytes
			result.Bytes += int64(advance)
		}
		return advance, token, err
	})
	for lines.Scan() {
		result.Lines++
		for _, finding := range scanner.Scan(lines.Bytes()) {
			group := byKind[finding.Kind]
			if group == nil {
				group = &kindReport{Kind: finding.Kind, DropOption: fmt.Sprintf("Use embargo.WithKinds with required kinds, omitting embargo.Kind(%q).", finding.Kind), Samples: []location{}}
				byKind[finding.Kind] = group
			}
			group.Count++
			if len(group.Samples) < sampleLimit {
				group.Samples = append(group.Samples, location{Value: "[REDACTED]", Start: lineStart + int64(finding.Start), End: lineStart + int64(finding.End), Line: result.Lines, Column: finding.Start})
			}
		}
	}
	if lines.Err() != nil {
		return report{}, errors.New("embargo-audit: input read failed or line reached the 4 MiB limit")
	}
	kinds := make([]embargo.Kind, 0, len(byKind))
	for kind := range byKind {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	for _, kind := range kinds {
		result.Findings = append(result.Findings, *byKind[kind])
	}
	return result, nil
}
