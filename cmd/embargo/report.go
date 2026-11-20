package main

import (
	"bufio"
	"encoding/json"
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

// writeReport prints per-kind counts and finding locations for --format json. Each line is
// discarded after scanning, so memory stays bounded, and input bytes are never
// printed. Incomplete input produces no report.
func writeReport(input io.Reader, output io.Writer, scanned *lineScanner, sampleLimit int) error {
	result, err := collectReport(input, scanned, sampleLimit)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return writeFailed(err)
	}
	return nil
}

func collectReport(input io.Reader, scanned *lineScanner, sampleLimit int) (report, error) {
	groups := make(map[embargo.Kind]*kindReport)
	counted := &pipeline{base: scanned, render: renderFindings, consequence: "no report is written", lines: 0, size: 0}
	err := counted.run(input, func(b *batch) error {
		for _, at := range b.found {
			addFinding(groups, at.finding, at.offset, at.line, sampleLimit)
		}
		return nil
	})
	if err != nil {
		return report{}, err
	}
	return report{Findings: sortedKinds(groups), Bytes: counted.size, Lines: counted.lines}, nil
}

// renderFindings keeps the findings of each line of b.
func renderFindings(lines *lineScanner, b *batch) {
	b.each(func(number int, offset int64, line []byte) {
		body, _ := splitEnding(line)
		for _, finding := range lines.scan(body) {
			b.found = append(b.found, located{finding: finding, offset: offset, line: number})
		}
	})
}

// foundValue is one --format jsonl line: where a finding is, never its value.
type foundValue struct {
	Kind   embargo.Kind `json:"kind"`
	Start  int64        `json:"start"`
	End    int64        `json:"end"`
	Line   int          `json:"line"`
	Column int          `json:"column"`
}

// writeFindings prints one JSON object per finding as each line is scanned and
// flushes whenever no more input is buffered, so tail -f works as with the
// filter. A read failure stops before that line, after the earlier findings.
func writeFindings(input io.Reader, output io.Writer, scanned *lineScanner) error {
	writer := bufio.NewWriterSize(output, ioBuffer)
	listed := &pipeline{base: scanned, render: renderFoundValues, consequence: "output stops before it", lines: 0, size: 0}
	return listed.run(input, func(b *batch) error { return writeBatch(writer, b) })
}

// renderFoundValues encodes one JSON line per finding of each line of b.
func renderFoundValues(lines *lineScanner, b *batch) {
	renderFindings(lines, b)
	for _, at := range b.found {
		place := newLocation(at.finding, at.offset, at.line)
		value := foundValue{Kind: at.finding.Kind, Start: place.Start, End: place.End, Line: place.Line, Column: place.Column}
		encoded, _ := json.Marshal(value) //nolint:errcheck // A struct of strings and integers always encodes.
		b.out = append(append(b.out, encoded...), '\n')
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
		group.Samples = append(group.Samples, newLocation(finding, lineStart, line))
	}
}

// newLocation places finding, found in the line that starts at byte offset
// lineStart, in the whole input.
func newLocation(finding embargo.Finding, lineStart int64, line int) location {
	return location{Start: lineStart + int64(finding.Start), End: lineStart + int64(finding.End), Line: line, Column: finding.Start}
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
