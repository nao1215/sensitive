package main

import (
	"errors"
	"flag"
	"io"
	"math"
	"strconv"
	"strings"
)

const (
	usage = `Usage: embargo [--format text|json|jsonl] [--input lines|csv|tsv] [--kinds all|KIND,...] [--min-confidence 0] [--samples 3] [file ...]
       embargo [--kinds all|KIND,...] [--min-confidence 0] run COMMAND [arg ...]

Masks secrets and personal data in each line of the files, or of stdin. No format prints a matched value.
run starts COMMAND with this stdin, masks its stdout and stderr separately and exits with its status.

  text   the masked lines (default). A line holding one JSON object or array keeps its keys,
         types and nesting and is written compact; lines keep their endings.
  json   one document with per-kind counts and up to --samples locations per kind.
  jsonl  one object per finding with its line, column, byte offsets and kind, as each line is read.

A read failure or a line longer than 4 MiB stops the output with an error. gzip and bzip2 input is
decompressed. A value whose key is on an earlier line of a JSON document or YAML block is masked too.

  --format F            output format: text, json or jsonl (default text)
  --input I             lines, or csv or tsv to read the first line as column names that work as keys
                        (default: csv or tsv when every file has that extension, otherwise lines)
  --kinds KIND,...      detect only these kinds; all selects every kind (default: the NewScanner defaults)
  --min-confidence N    drop findings below N, from 0 to 1 (default 0)
  --samples N           locations per kind with --format json, from 0 to 20 (default 3)
  --version             print the version
  --help                print this help

Flags come before the files; a file named - reads stdin, and -- ends the flags, so -- run reads a file named run.
Exit status: 0 done, 1 failed, 2 invalid usage, 141 output closed; run exits with the command's status, or 126/127 when it cannot start.
`
	maximumSamples = 20
	defaultSamples = 3
	kindsAllValue  = "all"
	formatText     = "text"
	formatJSON     = "json"
	formatJSONL    = "jsonl"
	runOperand     = "run"
)

// usageError is a message about the command line; it exits with status 2.
type usageError string

// Error returns the message.
func (e usageError) Error() string { return string(e) }

// options is the decoded and validated command line.
type options struct {
	kinds   string
	format  string
	input   string
	files   []string
	command []string
	minimum float64
	samples int
	version bool
}

// parseOptions decodes flags with the standard flag package. Errors name the
// flag and its allowed values but never repeat what was passed.
func parseOptions(args []string) (*options, error) {
	parsed := &options{kinds: "", input: "", files: nil, command: nil, minimum: 0, samples: defaultSamples, format: formatText, version: false}
	var minimumText, samplesText string
	flags := defineFlags(parsed, &minimumText, &samplesText)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, flagError(err)
	}
	minimum, ok := parseConfidence(minimumText)
	if !ok {
		return nil, usageError("embargo: --min-confidence must be a number from 0 to 1")
	}
	samples, err := strconv.Atoi(samplesText)
	if err != nil || samples < 0 || samples > maximumSamples {
		return nil, usageError("embargo: --samples must be an integer from 0 to 20")
	}
	if err := checkChoices(parsed); err != nil {
		return nil, err
	}
	samplesSet := false
	flags.Visit(func(f *flag.Flag) { samplesSet = samplesSet || f.Name == "samples" })
	if samplesSet && parsed.format != formatJSON {
		return nil, usageError("embargo: --samples requires --format json")
	}
	parsed.minimum, parsed.samples = minimum, samples
	return parsed, operands(parsed, args, flags.Args())
}

// defineFlags registers the flags, which fill parsed and the two texts that
// parseOptions checks as numbers.
func defineFlags(parsed *options, minimumText, samplesText *string) *flag.FlagSet {
	flags := flag.NewFlagSet("embargo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&parsed.kinds, "kinds", "", "")
	flags.StringVar(minimumText, "min-confidence", "0", "")
	flags.StringVar(&parsed.format, "format", formatText, "")
	flags.StringVar(&parsed.input, "input", "", "")
	flags.StringVar(samplesText, "samples", strconv.Itoa(defaultSamples), "")
	flags.BoolVar(&parsed.version, "version", false, "")
	return flags
}

// checkChoices checks the flags that take one of a few words.
func checkChoices(parsed *options) error {
	if parsed.format != formatText && parsed.format != formatJSON && parsed.format != formatJSONL {
		return usageError("embargo: --format must be text, json or jsonl")
	}
	if parsed.input != "" && parsed.input != inputLines && parsed.input != inputCSV && parsed.input != inputTSV {
		return usageError("embargo: --input must be lines, csv or tsv")
	}
	return nil
}

// operands reads what follows the flags: the files, or run and its command.
func operands(parsed *options, args, files []string) error {
	ended := endedFlags(args, files)
	if !ended && len(files) > 0 && files[0] == runOperand {
		parsed.command = files[1:]
		return commandUsage(parsed)
	}
	if !ended && lateFlag(files) {
		return usageError("embargo: flags must come before the files; see embargo --help")
	}
	parsed.files = files
	return nil
}

// endedFlags reports whether "--" ended the flags before files, after which
// every name is a file.
func endedFlags(args, files []string) bool {
	at := len(args) - len(files) - 1
	return at >= 0 && args[at] == "--"
}

// commandUsage checks the operands of run. Everything after run belongs to
// the command, and one "--" right after run is dropped, as in env.
func commandUsage(parsed *options) error {
	if len(parsed.command) > 0 && parsed.command[0] == "--" {
		parsed.command = parsed.command[1:]
	}
	if len(parsed.command) == 0 {
		return usageError("embargo: run needs a command; see embargo --help")
	}
	if parsed.format != formatText {
		return usageError("embargo: run writes text only; --format cannot be used with it")
	}
	if parsed.input != "" {
		return usageError("embargo: run reads lines only; --input cannot be used with it")
	}
	return nil
}

// lateFlag reports whether a file name looks like a flag. The flag package
// stops at the first file, so "a.log --kinds email" would read --kinds as a
// file; "-" is stdin.
func lateFlag(files []string) bool {
	for _, name := range files {
		if strings.HasPrefix(name, "-") && name != stdinName {
			return true
		}
	}
	return false
}

func parseConfidence(text string) (float64, bool) {
	value, err := strconv.ParseFloat(text, 64)
	return value, err == nil && !math.IsNaN(value) && value >= 0 && value <= 1
}

// flagError names the flag when the flag package reports a defined one, as in
// "flag needs an argument: -kinds"; an undefined name is what was typed, so it
// is not repeated and the defined flags are listed instead.
func flagError(err error) error {
	text := err.Error()
	for _, name := range []string{"kinds", "min-confidence", "format", "input", "samples", "version"} {
		if strings.HasSuffix(text, ": -"+name) || strings.Contains(text, " for -"+name+":") {
			if strings.HasPrefix(text, "flag needs an argument") {
				return usageError("embargo: --" + name + " needs a value; see embargo --help")
			}
			return usageError("embargo: --" + name + " has an invalid value; see embargo --help")
		}
	}
	return usageError("embargo: unknown flag; the flags are --kinds, --min-confidence, --format, --input, --samples and --version; see embargo --help")
}
