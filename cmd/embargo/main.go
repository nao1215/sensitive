package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/nao1215/embargo"
)

const kindsHelp = "Kinds and matching rules: https://pkg.go.dev/github.com/nao1215/embargo#Kind\n"

func main() { os.Exit(exitCode(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func exitCode(args []string, input io.Reader, output, diagnostics io.Writer) int {
	if err := run(args, input, output); err != nil {
		_, _ = fmt.Fprintln(diagnostics, err) //nolint:errcheck // The status is already 1; a failed diagnostic write cannot change it.
		return 1
	}
	return 0
}

// run masks lines by default; --format json and jsonl report findings instead.
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
	switch parsed.format {
	case formatJSON:
		return writeReport(source, output, scanner, parsed.samples)
	case formatJSONL:
		return writeFindings(source, output, scanner)
	default:
		return filterLines(source, output, scanner)
	}
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
	if info, ok := debug.ReadBuildInfo(); ok {
		version = cmp.Or(info.Main.Version, version)
	}
	_, err := fmt.Fprintln(output, "embargo", version)
	return err
}

// selectedScanner builds the scanner for --kinds: empty is the default set and
// all selects every kind. WithKinds panics on an unknown public Kind string;
// only that call is recovered, into a fixed diagnostic that never echoes the
// argument, so any other panic still crashes.
func selectedScanner(kinds string, minimum float64) (*embargo.Scanner, error) {
	options := []embargo.ScannerOption{embargo.WithMinConfidence(minimum)}
	switch kinds {
	case "":
	case kindsAllValue:
		options = append(options, embargo.WithAll())
	default:
		selection := make([]embargo.Kind, 0, strings.Count(kinds, ",")+1)
		for kind := range strings.SplitSeq(kinds, ",") {
			selection = append(selection, embargo.Kind(strings.TrimSpace(kind)))
		}
		option, ok := kindsOption(selection)
		if !ok {
			return nil, errors.New("embargo: --kinds must be all or a comma-separated list of kinds; see embargo --help")
		}
		options = append(options, option)
	}
	return embargo.NewScanner(options...), nil
}

// kindsOption returns embargo.WithKinds(selection), or false when it rejects
// an unknown kind.
func kindsOption(selection []embargo.Kind) (option embargo.ScannerOption, ok bool) {
	defer func() {
		if recover() != nil {
			option, ok = nil, false
		}
	}()
	return embargo.WithKinds(selection...), true
}
