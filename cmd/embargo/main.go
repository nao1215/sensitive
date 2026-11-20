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

// Exit statuses besides a command's own: closedOutput is what a shell reports
// for a filter that SIGPIPE ended, as when the reader is head.
const (
	statusFailed       = 1
	statusUsage        = 2
	statusClosedOutput = 141
)

func main() { os.Exit(exitCode(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// exitCode runs the command line and turns its error into the exit status. A
// closed output says nothing, since its reader has gone and the shell knows.
func exitCode(args []string, input io.Reader, output, diagnostics io.Writer) int {
	err := run(args, input, output, diagnostics)
	if err == nil {
		return 0
	}
	if errors.Is(err, errOutputClosed) {
		return statusClosedOutput
	}
	code := statusFailed
	if status, ok := errors.AsType[statusError](err); ok {
		if status.cause == nil {
			return status.code
		}
		code, err = status.code, status.cause
	} else if errors.As(err, new(usageError)) {
		code = statusUsage
	}
	_, _ = fmt.Fprintln(diagnostics, err) //nolint:errcheck // The status is already set; a failed diagnostic write cannot change it.
	return code
}

// run masks lines by default; --format json and jsonl report findings
// instead, and run masks what a command prints to output and diagnostics.
func run(args []string, input io.Reader, output, diagnostics io.Writer) error {
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
	if parsed.command != nil {
		return runCommand(parsed.command, scanner, input, output, diagnostics)
	}
	source, closeInputs := openInputs(parsed.files, input)
	defer closeInputs()
	lines := newLineScanner(scanner, inputMode(parsed.input, parsed.files))
	switch parsed.format {
	case formatJSON:
		return writeReport(source, output, lines, parsed.samples)
	case formatJSONL:
		return writeFindings(source, output, lines)
	default:
		return filterLines(source, output, lines)
	}
}

func writeUsage(output io.Writer) error {
	if _, err := io.WriteString(output, usage); err != nil {
		return writeFailed(err)
	}
	if _, err := io.WriteString(output, kindsHelp); err != nil {
		return writeFailed(err)
	}
	return nil
}

func writeVersion(output io.Writer) error {
	version := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok {
		version = cmp.Or(info.Main.Version, version)
	}
	if _, err := fmt.Fprintln(output, "embargo", version); err != nil {
		return writeFailed(err)
	}
	return nil
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
		option, message := kindsOption(selection)
		if option == nil {
			return nil, usageError("embargo: --kinds must be all or a comma-separated list of kinds" + message + "; see embargo --help")
		}
		options = append(options, option)
	}
	return embargo.NewScanner(options...), nil
}

// kindsOption returns the selection, or nil and the part of WithKinds' panic
// that names the unknown kind, such as ` "emial"`.
func kindsOption(selection []embargo.Kind) (option embargo.ScannerOption, unknown string) {
	defer func() {
		if value := recover(); value != nil {
			option = nil
			if text, ok := value.(string); ok {
				if kind, found := strings.CutPrefix(text, "embargo: unknown built-in kind"); found && kind != "" {
					unknown = "; unknown kind" + kind
				}
			}
		}
	}()
	return embargo.WithKinds(selection...), ""
}
