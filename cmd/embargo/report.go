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

// writeReport prints per-kind counts and finding locations for --format json. Each line is
// discarded after scanning, so memory stays bounded, and input bytes are never
// printed. Incomplete input produces no report.
func writeReport(input io.Reader, output io.Writer, scanner *embargo.Scanner, sampleLimit int) error {
	result, err := collectReport(input, scanner, sampleLimit)
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

func collectReport(input io.Reader, scanner *embargo.Scanner, sampleLimit int) (report, error) {
	groups := make(map[embargo.Kind]*kindReport)
	scanned := &lineScanner{scanner: scanner}
	lines, size, err := eachLine(bufio.NewReaderSize(input, ioBuffer), "no report is written", func(number int, offset int64, body []byte) error {
		for _, finding := range scanned.scan(body) {
			addFinding(groups, finding, offset, number, sampleLimit)
		}
		return nil
	})
	if err != nil {
		return report{}, err
	}
	return report{Findings: sortedKinds(groups), Bytes: size, Lines: lines}, nil
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
func writeFindings(input io.Reader, output io.Writer, scanner *embargo.Scanner) error {
	reader := bufio.NewReaderSize(input, ioBuffer)
	writer := bufio.NewWriterSize(output, ioBuffer)
	encoder := json.NewEncoder(writer)
	scanned := &lineScanner{scanner: scanner}
	_, _, err := eachLine(reader, "output stops before it", func(number int, offset int64, body []byte) error {
		for _, f := range scanned.scan(body) {
			at := newLocation(f, offset, number)
			value := foundValue{Kind: f.Kind, Start: at.Start, End: at.End, Line: at.Line, Column: at.Column}
			if err := encoder.Encode(value); err != nil {
				return writeFailed(err)
			}
		}
		if reader.Buffered() == 0 {
			if err := writer.Flush(); err != nil {
				return writeFailed(err)
			}
		}
		return nil
	})
	return flushThen(writer, err)
}

// eachLine reads lines exactly as the filter does and calls fn with each
// line's number, the byte offset where it starts and its body without the
// ending. It returns the line count and total size, or the first read failure,
// whose message ends with consequence, or fn's error.
func eachLine(reader *bufio.Reader, consequence string, fn func(number int, offset int64, body []byte) error) (lines int, size int64, err error) {
	for number := 1; ; number++ {
		line, tooLong, readErr := readLine(reader)
		if failure := readFailure(tooLong, readErr, number, consequence); failure != nil {
			return lines, size, failure
		}
		if len(line) > 0 {
			lines++
			body, _ := splitEnding(line)
			if err := fn(number, size, body); err != nil {
				return lines, size, err
			}
			size += int64(len(line))
		}
		if errors.Is(readErr, io.EOF) {
			return lines, size, nil
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
