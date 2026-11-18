package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/nao1215/embargo"
)

type location struct {
	Start  int64 `json:"start"`
	End    int64 `json:"end"`
	Line   int   `json:"line"`
	Column int   `json:"column"`
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

// writeReport prints per-kind counts and masked locations. Each line is
// discarded after scanning, so memory stays bounded, and input bytes are never
// printed. Incomplete input produces no report.
func writeReport(input io.Reader, output io.Writer, scanner *embargo.Scanner, sampleLimit int) error {
	result, err := collectReport(input, scanner, sampleLimit)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func collectReport(input io.Reader, scanner *embargo.Scanner, sampleLimit int) (report, error) {
	groups := make(map[embargo.Kind]*kindReport)
	// The report reads lines exactly as the filter does, so both accept the
	// same input and count the same lines.
	reader := bufio.NewReaderSize(input, ioBuffer)
	var bytesRead int64
	lineCount := 0
	for number := 1; ; number++ {
		line, tooLong, readErr := readLine(reader)
		if failure := readFailure(tooLong, readErr, number, "no report is written"); failure != nil {
			return report{}, failure
		}
		if len(line) > 0 {
			lineCount++
			body, _ := splitEnding(line)
			for _, finding := range scanner.Scan(body) {
				addFinding(groups, finding, bytesRead, lineCount, sampleLimit)
			}
			bytesRead += int64(len(line))
		}
		if errors.Is(readErr, io.EOF) {
			return report{Findings: sortedKinds(groups), Bytes: bytesRead, Lines: lineCount}, nil
		}
	}
}

func addFinding(groups map[embargo.Kind]*kindReport, finding embargo.Finding, lineStart int64, line, sampleLimit int) {
	group := groups[finding.Kind]
	if group == nil {
		group = &kindReport{Kind: finding.Kind, DropOption: fmt.Sprintf("Pass --kinds with the kinds you need, leaving out %s.", finding.Kind), Samples: []location{}, Count: 0}
		groups[finding.Kind] = group
	}
	group.Count++
	if len(group.Samples) < sampleLimit {
		group.Samples = append(group.Samples, location{Start: lineStart + int64(finding.Start), End: lineStart + int64(finding.End), Line: line, Column: finding.Start})
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
