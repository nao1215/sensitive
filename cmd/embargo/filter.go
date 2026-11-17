package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

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
	for number := 1; ; number++ {
		line, tooLong, readErr := readLine(reader)
		if failure := readFailure(tooLong, readErr, number); failure != nil {
			return flushThen(writer, failure)
		}
		if err := writeMaskedLine(writer, scanner, line); err != nil {
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

// readFailure turns a stopped read into the message for line number, or nil
// when the line was read in full, including the final one at io.EOF.
func readFailure(tooLong bool, readErr error, number int) error {
	if tooLong {
		return fmt.Errorf("embargo: line %d exceeds the 4 MiB limit; output stops before it", number)
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return safeInputError(readErr, fmt.Sprintf("embargo: input read failed at line %d", number))
	}
	return nil
}

// writeMaskedLine writes one masked line followed by its original ending.
func writeMaskedLine(writer *bufio.Writer, scanner *embargo.Scanner, line []byte) error {
	if len(line) == 0 {
		return nil
	}
	body, ending := splitEnding(line)
	_, err := writer.Write(maskLine(scanner, body))
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
// its shape and the sensitive key policy; any other line, and JSON that
// MaskJSON rejects, is masked as text, which never returns the input unmasked.
func maskLine(scanner *embargo.Scanner, body []byte) []byte {
	if trimmed := bytes.TrimLeft(body, " \t"); len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		if masked, err := scanner.MaskJSON(body); err == nil {
			return masked
		}
	}
	return []byte(embargo.Mask(string(body), scanner.Scan(body)))
}
