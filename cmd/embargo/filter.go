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

// filterLines masks line by line. Output is flushed whenever the reader has no
// buffered input left, so a pipe such as tail -f sees each line as it arrives.
// A read failure or an over-long line stops before that line: nothing after a
// failure is written, and the error names only the line number.
func filterLines(input io.Reader, output io.Writer, scanner *embargo.Scanner) error {
	reader := bufio.NewReaderSize(input, ioBuffer)
	writer := bufio.NewWriterSize(output, ioBuffer)
	lines := &lineScanner{scanner: scanner}
	for number := 1; ; number++ {
		line, tooLong, readErr := readLine(reader)
		if failure := readFailure(tooLong, readErr, number, "output stops before it"); failure != nil {
			return flushThen(writer, failure)
		}
		if err := writeMaskedLine(writer, lines, line); err != nil {
			return err
		}
		done := errors.Is(readErr, io.EOF)
		if (done || reader.Buffered() == 0) && writer.Flush() != nil {
			return errors.New("embargo: output write failed")
		}
		if done {
			return nil
		}
	}
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

// writeMaskedLine writes one masked line followed by its original ending.
func writeMaskedLine(writer *bufio.Writer, lines *lineScanner, line []byte) error {
	if len(line) == 0 {
		return nil
	}
	body, ending := splitEnding(line)
	_, err := writer.Write(maskLine(lines, body))
	if err == nil {
		_, err = writer.Write(ending)
	}
	if err != nil {
		return errors.New("embargo: output write failed")
	}
	return nil
}

func flushThen(writer *bufio.Writer, err error) error {
	if flushErr := writer.Flush(); flushErr != nil {
		return errors.New("embargo: output write failed")
	}
	return err
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
// A line inside an open PEM block is always masked as text.
func maskLine(lines *lineScanner, body []byte) []byte {
	if trimmed := bytes.TrimLeft(body, " \t"); !lines.open() && len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		if masked, err := lines.scanner.MaskJSON(body); err == nil {
			lines.observe(body)
			return masked
		}
	}
	return []byte(embargo.Mask(string(body), lines.scan(body)))
}

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
	scanner *embargo.Scanner
	header  []byte
}

func (l *lineScanner) open() bool { return l.header != nil }

// observe records a block opened by a line whose findings were not needed.
func (l *lineScanner) observe(body []byte) {
	if bytes.Contains(body, []byte(pemHint)) {
		l.scan(body)
	}
}

// scan returns line-relative findings for body, including the part of an open
// PEM block that covers it.
func (l *lineScanner) scan(body []byte) []embargo.Finding {
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
