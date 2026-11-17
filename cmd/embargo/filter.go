package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/nao1215/embargo"
)

const (
	filterUsage = "Usage: embargo [--kinds email,pan] [--all] [--min-confidence 0] [file ...]\n       embargo audit [flags] [file ...]\n\nMasks secrets and personal data in each line of the files, or of stdin, and writes the lines to stdout.\nA line holding one JSON document keeps its keys, types and nesting and is written compact.\nLines keep their endings. A line longer than 4 MiB stops the output with an error.\n"
	// maximumLine bounds one line's memory; MaskJSON accepts at most 1 MiB and
	// longer JSON lines are masked as text.
	maximumLine = 4 << 20
	ioBuffer    = 64 << 10
)

type filterOptions struct {
	kinds, minimumText string
	all, version       bool
}

func parseFilterOptions(args []string) (*filterOptions, []string, error) {
	options := &filterOptions{kinds: "", minimumText: "", all: false, version: false}
	flags := flag.NewFlagSet("embargo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.kinds, "kinds", "", "comma-separated kinds; default kind set if omitted")
	flags.BoolVar(&options.all, "all", false, "include opt-in country and entropy kinds")
	flags.StringVar(&options.minimumText, "min-confidence", "0", "inclusive minimum detector confidence")
	flags.BoolVar(&options.version, "version", false, "print the version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil, err
		}
		return nil, nil, errors.New("embargo: invalid flags\nUsage: embargo [--kinds email,pan] [--all] [--min-confidence 0] [file ...]; use --help for options")
	}
	if options.all && options.kinds != "" {
		return nil, nil, errors.New("embargo: --all and --kinds cannot be combined")
	}
	return options, flags.Args(), nil
}

// runFilter writes every input line masked, in input order.
func runFilter(args []string, input io.Reader, output io.Writer) error {
	options, files, err := parseFilterOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		return writeUsage(output, filterUsage)
	}
	if err != nil {
		return err
	}
	if options.version {
		return writeVersion(output)
	}
	minimum, ok := parseConfidence(options.minimumText)
	if !ok {
		return errors.New("embargo: --min-confidence must be between 0 and 1")
	}
	scanner, err := selectedScanner(options.kinds, options.all, minimum, "embargo: --kinds")
	if err != nil {
		return err
	}
	source, closeInputs := openInputs(files, input)
	defer closeInputs()
	return filterLines(source, output, scanner)
}

// filterLines masks line by line. Output is flushed whenever the reader has no
// buffered input left, so a pipe such as tail -f sees each line as it arrives.
// A read failure or an over-long line stops before that line: nothing after a
// failure is written, and the error names only the line number.
func filterLines(input io.Reader, output io.Writer, scanner *embargo.Scanner) error {
	reader := bufio.NewReaderSize(input, ioBuffer)
	writer := bufio.NewWriterSize(output, ioBuffer)
	for number := 1; ; number++ {
		line, tooLong, readErr := readLine(reader)
		if tooLong {
			return flushThen(writer, fmt.Errorf("embargo: line %d exceeds the 4 MiB limit; output stops before it", number))
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return flushThen(writer, fmt.Errorf("embargo: input read failed at line %d", number))
		}
		if len(line) > 0 {
			body, ending := splitEnding(line)
			_, err := writer.Write(maskLine(scanner, body))
			if err == nil {
				_, err = writer.Write(ending)
			}
			if err != nil {
				return errors.New("embargo: output write failed")
			}
		}
		if errors.Is(readErr, io.EOF) || reader.Buffered() == 0 {
			if err := writer.Flush(); err != nil {
				return errors.New("embargo: output write failed")
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
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
