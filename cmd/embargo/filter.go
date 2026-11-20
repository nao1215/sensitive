package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/nao1215/embargo"
)

// maximumLine bounds one line's memory; MaskJSON accepts at most 1 MiB and
// longer JSON lines are masked as text.
const (
	maximumLine = 4 << 20
	ioBuffer    = 64 << 10
)

// errOutputClosed reports that the reader of the output has gone, as when the
// output is piped into head; it ends the command quietly with status 141.
var errOutputClosed = errors.New("embargo: output closed")

// writeFailed returns errOutputClosed for a reader that has gone and a fixed
// error for any other write failure, whose text could name a path.
func writeFailed(err error) error {
	if outputClosed(err) {
		return errOutputClosed
	}
	return errors.New("embargo: output write failed")
}

// filterLines masks line by line. Output is flushed whenever the reader has no
// buffered input left, so a pipe such as tail -f sees each line as it arrives.
// A read failure or an over-long line stops before that line: nothing after a
// failure is written, and the error names only the line number.
func filterLines(input io.Reader, output io.Writer, lines *lineScanner) error {
	writer := bufio.NewWriterSize(output, ioBuffer)
	masked := &pipeline{base: lines, render: renderMasked, consequence: "output stops before it", lines: 0, size: 0}
	return masked.run(input, func(b *batch) error { return writeBatch(writer, b) })
}

// renderMasked writes each masked line followed by its original ending.
func renderMasked(lines *lineScanner, b *batch) {
	b.each(func(_ int, _ int64, line []byte) {
		body, ending := splitEnding(line)
		b.out = append(append(b.out, maskLine(lines, body)...), ending...)
	})
}

// writeBatch writes the output of b, flushing when b is the last input
// buffered.
func writeBatch(writer *bufio.Writer, b *batch) error {
	if _, err := writer.Write(b.out); err != nil {
		return writeFailed(err)
	}
	if b.flush {
		if err := writer.Flush(); err != nil {
			return writeFailed(err)
		}
	}
	return nil
}

// readFailure turns a stopped read into the message for line number, ending
// with what happens to the output, or nil when the line was read in full,
// including the final one at io.EOF.
func readFailure(tooLong bool, readErr error, number int, consequence string) error {
	if tooLong {
		return fmt.Errorf("embargo: line %d exceeds the 4 MiB limit; %s", number, consequence)
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return safeInputError(readErr, fmt.Sprintf("embargo: input read failed at line %d; %s", number, consequence))
	}
	return nil
}

// readLine returns one line including its newline, or the final unterminated
// bytes with io.EOF. It reports tooLong instead of returning a line longer than
// maximumLine.
func readLine(reader *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, readErr := reader.ReadSlice('\n')
		if len(line)+len(chunk) > maximumLine {
			return nil, true, nil
		}
		if !errors.Is(readErr, bufio.ErrBufferFull) {
			if line == nil {
				return chunk, false, readErr
			}
			return append(line, chunk...), false, readErr
		}
		line = append(line, chunk...)
	}
}

// splitEnding separates a trailing "\n" or "\r\n" so it is written unchanged.
func splitEnding(line []byte) (body, ending []byte) {
	if !bytes.HasSuffix(line, []byte("\n")) {
		return line, nil
	}
	end := len(line) - 1
	if end > 0 && line[end-1] == '\r' {
		end--
	}
	return line[:end], line[end:]
}

// maskLine uses MaskJSON for a line holding one JSON object or array, keeping
// its shape and the sensitive key policy. Any other line, and JSON that
// MaskJSON rejects, is masked as text: detected values are replaced, the
// sensitive key policy does not apply, and a line without findings is written
// unchanged.
// A line inside an open PEM block is always masked as text. A UTF-8 byte
// order mark, as Windows editors write before the first line, is kept and the
// rest of the line is masked as if it were not there.
func maskLine(lines *lineScanner, body []byte) []byte {
	if bytes.HasPrefix(body, []byte(utf8BOM)) {
		return append([]byte(utf8BOM), maskLine(lines, body[len(utf8BOM):])...)
	}
	if trimmed := bytes.TrimLeft(body, " \t"); lines.table == nil && !lines.open() && len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		if masked, err := lines.scanner.MaskJSON(body); err == nil {
			lines.observe(body)
			return masked
		}
	}
	return []byte(embargo.Mask(string(body), lines.scan(body)))
}

// utf8BOM is the UTF-8 byte order mark.
const utf8BOM = "\xef\xbb\xbf"

// pemHeaderLimit bounds the retained start of an open PEM block; a header cut
// at the limit still reads as an open block, so truncation only masks more.
const pemHeaderLimit = 1 << 10

// pemHint is a byte sequence every PEM and PGP BEGIN header contains, also in
// its percent-encoded and escaped forms, so JSON lines without it skip the
// extra scan that looks for a block left open at the line end.
const pemHint = "BEGIN"

// pemProbe follows a retained header so that a block still open at the end of
// a scanned text covers this line, and a closed block stops before it.
const pemProbe = "\nx"

// lineScanner scans one line at a time like Scanner.ScanLines: a PEM block
// whose END line has not arrived yet covers the following lines. It keeps the
// start of the open block and rescans it together with each new line, so the
// root detectors decide where the block ends.
type lineScanner struct {
	scanner   *embargo.Scanner
	structure *structure
	// table reads CSV or TSV records instead of the structures, when set.
	table  *table
	header []byte
}

// newLineScanner scans lines of the given --input mode.
func newLineScanner(scanner *embargo.Scanner, mode string) *lineScanner {
	lines := &lineScanner{scanner: scanner, structure: newStructure(scanner), table: nil, header: nil}
	switch mode {
	case inputCSV:
		lines.table = newTable(scanner, ',')
	case inputTSV:
		lines.table = newTable(scanner, '\t')
	}
	return lines
}

// open reports whether an earlier line left a PEM block, a JSON document or
// a YAML block open, so this line belongs to it.
func (l *lineScanner) open() bool { return l.header != nil || l.structure.open() }

// observe records a block opened by a line whose findings were not needed.
func (l *lineScanner) observe(body []byte) {
	if bytes.Contains(body, []byte(pemHint)) {
		l.scanPEM(body)
	}
}

// scan returns line-relative findings for body, including the part of an open
// PEM block that covers it.
func (l *lineScanner) scan(body []byte) []embargo.Finding {
	if l.table != nil {
		return mergeFindings(l.scanPEM(body), l.table.findings(body))
	}
	return mergeFindings(l.scanPEM(body), l.structure.findings(body))
}

// scanPEM is scan without the structures around the line.
func (l *lineScanner) scanPEM(body []byte) []embargo.Finding {
	if l.header == nil {
		findings := l.scanner.Scan(body)
		l.header = l.opened(body, findings)
		return findings
	}
	offset := len(l.header) + 1
	joined := slices.Concat(l.header, []byte("\n"), body, []byte(pemProbe))
	findings := []embargo.Finding{}
	continuing := false
	for _, f := range l.scanner.Scan(joined) {
		if f.Kind == embargo.KindPrivateKeyPEM && f.Start < offset && f.End == len(joined) {
			continuing = true
		}
		start, end := max(f.Start-offset, 0), min(f.End-offset, len(body))
		if start < end {
			findings = append(findings, embargo.Finding{Kind: f.Kind, Start: start, End: end, Confidence: f.Confidence})
		}
	}
	if !continuing {
		l.header = l.opened(body, findings)
	}
	return findings
}

// opened returns the start of a PEM block that reaches the end of body without
// its END line, or nil.
func (l *lineScanner) opened(body []byte, findings []embargo.Finding) []byte {
	for _, f := range findings {
		if f.Kind != embargo.KindPrivateKeyPEM || f.End != len(body) {
			continue
		}
		header := body[f.Start:min(len(body), f.Start+pemHeaderLimit)]
		probe := slices.Concat(header, []byte(pemProbe))
		for _, g := range l.scanner.Scan(probe) {
			if g.Kind == embargo.KindPrivateKeyPEM && g.Start == 0 && g.End == len(probe) {
				return slices.Clone(header)
			}
		}
	}
	return nil
}
