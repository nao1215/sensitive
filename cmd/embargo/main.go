package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/nao1215/embargo"
)

const kindsHelp = "Kinds and matching rules: https://pkg.go.dev/github.com/nao1215/embargo#Kind\n"

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

// run masks lines by default; --report prints finding counts instead.
func run(args []string, input io.Reader, output io.Writer) error {
	parsed, err := parseOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		return writeUsage(output)
	}
	if err != nil {
		return err
	}
	if parsed.version {
		return writeVersion(output)
	}
	scanner, err := selectedScanner(parsed.kinds, parsed.minimum)
	if err != nil {
		return err
	}
	source, closeInputs := openInputs(parsed.files, input)
	defer closeInputs()
	if parsed.report {
		return writeReport(source, output, scanner, parsed.samples)
	}
	return filterLines(source, output, scanner)
}

func writeUsage(output io.Writer) error {
	if _, err := io.WriteString(output, usage); err != nil {
		return err
	}
	_, err := io.WriteString(output, kindsHelp)
	return err
}

func writeVersion(output io.Writer) error {
	version := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		version = info.Main.Version
	}
	_, err := fmt.Fprintln(output, "embargo", version)
	return err
}

// selectedScanner builds the scanner for --kinds: empty is the default set and
// all selects every kind. WithKinds rejects unknown public Kind strings; only
// that input error becomes a fixed diagnostic, so arguments are never echoed.
func selectedScanner(kinds string, minimum float64) (scanner *embargo.Scanner, err error) {
	defer func() {
		if recover() != nil {
			scanner = nil
			err = errors.New("embargo: --kinds must be all or a comma-separated list of kinds; see embargo --help")
		}
	}()
	options := []embargo.ScannerOption{embargo.WithMinConfidence(minimum)}
	switch kinds {
	case "":
	case "all":
		options = append(options, embargo.WithAll())
	default:
		selection := make([]embargo.Kind, 0, strings.Count(kinds, ",")+1)
		for kind := range strings.SplitSeq(kinds, ",") {
			selection = append(selection, embargo.Kind(strings.TrimSpace(kind)))
		}
		options = append(options, embargo.WithKinds(selection...))
	}
	return embargo.NewScanner(options...), nil
}

func parseConfidence(text string) (float64, bool) {
	value, err := strconv.ParseFloat(text, 64)
	return value, err == nil && !math.IsNaN(value) && value >= 0 && value <= 1
}

// openInputs reads the named files in order, like cat, or stdin when there are
// none. Files open one at a time; a file that cannot be read stops the input
// with a fixed error that does not repeat its name.
func openInputs(names []string, stdin io.Reader) (source io.Reader, closeAll func()) {
	if len(names) == 0 {
		return stdin, func() {}
	}
	files := &fileSequence{names: names, current: nil, closeErr: nil}
	return files, files.close
}

// inputError is a fixed message about the named input files; it never holds a
// file name or operating-system detail, so it is shown as is.
type inputError string

// Error returns the fixed message.
func (e inputError) Error() string { return string(e) }

// safeInputError returns err's own message when it is an inputError and
// fallback otherwise, so reader errors from other sources are never shown.
func safeInputError(err error, fallback string) error {
	if message, ok := errors.AsType[inputError](err); ok {
		return message
	}
	return errors.New(fallback)
}

type fileSequence struct {
	current  *os.File
	closeErr error
	names    []string
}

// Read reads the files in order and reports io.EOF after the last one.
func (f *fileSequence) Read(p []byte) (int, error) {
	for {
		if err := f.advance(); err != nil {
			return 0, err
		}
		n, err := f.current.Read(p)
		if !errors.Is(err, io.EOF) {
			if err != nil {
				return n, inputError("embargo: an input file cannot be read")
			}
			return n, nil
		}
		f.close()
		if n > 0 {
			return n, nil
		}
	}
}

// advance opens the next file when none is open, returning io.EOF after the
// last one and a fixed error for a file that cannot be opened or closed.
func (f *fileSequence) advance() error {
	if f.closeErr != nil {
		return inputError("embargo: an input file cannot be closed")
	}
	if f.current != nil {
		return nil
	}
	if len(f.names) == 0 {
		return io.EOF
	}
	file, err := os.Open(f.names[0])
	if err != nil {
		return inputError("embargo: an input file cannot be opened")
	}
	f.current, f.names = file, f.names[1:]
	return nil
}

// close releases the current file; a failure is reported by the next Read.
func (f *fileSequence) close() {
	if f.current == nil {
		return
	}
	f.closeErr = f.current.Close()
	f.current = nil
}
