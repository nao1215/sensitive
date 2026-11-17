package main

import (
	"errors"
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

// run masks lines by default; "embargo audit" reports findings instead.
func run(args []string, input io.Reader, output io.Writer) error {
	if len(args) > 0 && args[0] == "audit" {
		return runAudit(args[1:], input, output)
	}
	return runFilter(args, input, output)
}

func writeUsage(output io.Writer, usage string) error {
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

// selectedScanner builds the scanner for a kind selection. WithKinds rejects
// unknown public Kind strings; only that input error becomes a fixed
// diagnostic, so possibly sensitive arguments are never echoed.
func selectedScanner(kinds string, all bool, minimum float64, flagName string) (scanner *embargo.Scanner, err error) {
	defer func() {
		if recover() != nil {
			scanner = nil
			err = errors.New(flagName + " contains an unknown kind; use --help for kinds")
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

func parseConfidence(text string) (float64, bool) {
	value, err := strconv.ParseFloat(text, 64)
	return value, err == nil && !math.IsNaN(value) && value >= 0 && value <= 1
}

// openInputs reads the named files in order, like cat, or stdin when there are
// none. Files open one at a time; a file that cannot be read stops the input
// with a fixed error that does not repeat its name.
func openInputs(names []string, stdin io.Reader) (io.Reader, func()) {
	if len(names) == 0 {
		return stdin, func() {}
	}
	files := &fileSequence{names: names, current: nil, closeErr: nil}
	return files, files.close
}

type fileSequence struct {
	current  *os.File
	closeErr error
	names    []string
}

func (f *fileSequence) Read(p []byte) (int, error) {
	for {
		if f.closeErr != nil {
			return 0, errors.New("embargo: an input file cannot be closed")
		}
		if f.current == nil {
			if len(f.names) == 0 {
				return 0, io.EOF
			}
			file, err := os.Open(f.names[0])
			if err != nil {
				return 0, errors.New("embargo: an input file cannot be opened")
			}
			f.current, f.names = file, f.names[1:]
		}
		n, err := f.current.Read(p)
		if errors.Is(err, io.EOF) {
			f.close()
			if n > 0 {
				return n, nil
			}
			continue
		}
		if err != nil {
			return n, errors.New("embargo: an input file cannot be read")
		}
		return n, nil
	}
}

// close releases the current file; a failure is reported by the next Read.
func (f *fileSequence) close() {
	if f.current == nil {
		return
	}
	f.closeErr = f.current.Close()
	f.current = nil
}
