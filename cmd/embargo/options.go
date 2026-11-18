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
	usage = `Usage: embargo [--format text|json|jsonl] [--kinds all|KIND,...] [--min-confidence 0] [--samples 3] [file ...]

Masks secrets and personal data in each line of the files, or of stdin. No format prints a matched value.

  text   the masked lines (default). A line holding one JSON object or array keeps its keys,
         types and nesting and is written compact; lines keep their endings.
  json   one document with per-kind counts and up to --samples locations per kind.
  jsonl  one object per finding with its line, column, byte offsets and kind, as each line is read.

A read failure or a line longer than 4 MiB stops the output with an error.

  --format F            output format: text, json or jsonl (default text)
  --kinds KIND,...      detect only these kinds; all selects every kind (default: the NewScanner defaults)
  --min-confidence N    drop findings below N, from 0 to 1 (default 0)
  --samples N           locations per kind with --format json, from 0 to 20 (default 3)
  --version             print the version
  --help                print this help

Flags come before the files; a file named - reads stdin, and -- ends the flags.
`
	maximumSamples = 20
	defaultSamples = 3
	kindsAllValue  = "all"
	formatText     = "text"
	formatJSON     = "json"
	formatJSONL    = "jsonl"
)

// options is the decoded and validated command line.
type options struct {
	kinds   string
	format  string
	files   []string
	minimum float64
	samples int
	version bool
}

// parseOptions decodes flags with the standard flag package. Errors name the
// flag and its allowed values but never repeat what was passed.
func parseOptions(args []string) (*options, error) {
	parsed := &options{kinds: "", files: nil, minimum: 0, samples: defaultSamples, format: formatText, version: false}
	var minimumText, samplesText string
	flags := flag.NewFlagSet("embargo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&parsed.kinds, "kinds", "", "")
	flags.StringVar(&minimumText, "min-confidence", "0", "")
	flags.StringVar(&parsed.format, "format", formatText, "")
	flags.StringVar(&samplesText, "samples", strconv.Itoa(defaultSamples), "")
	flags.BoolVar(&parsed.version, "version", false, "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, flagError(err)
	}
	minimum, ok := parseConfidence(minimumText)
	if !ok {
		return nil, errors.New("embargo: --min-confidence must be a number from 0 to 1")
	}
	samples, err := strconv.Atoi(samplesText)
	if err != nil || samples < 0 || samples > maximumSamples {
		return nil, errors.New("embargo: --samples must be an integer from 0 to 20")
	}
	if parsed.format != formatText && parsed.format != formatJSON && parsed.format != formatJSONL {
		return nil, errors.New("embargo: --format must be text, json or jsonl")
	}
	samplesSet := false
	flags.Visit(func(f *flag.Flag) { samplesSet = samplesSet || f.Name == "samples" })
	if samplesSet && parsed.format != formatJSON {
		return nil, errors.New("embargo: --samples requires --format json")
	}
	files := flags.Args()
	if lateFlag(args, files) {
		return nil, errors.New("embargo: flags must come before the files; see embargo --help")
	}
	parsed.minimum, parsed.samples, parsed.files = minimum, samples, files
	return parsed, nil
}

// lateFlag reports whether a file name looks like a flag. The flag package
// stops at the first file, so "a.log --kinds email" would read --kinds as a
// file; "-" is stdin, and after "--" every name is a file.
func lateFlag(args, files []string) bool {
	if at := len(args) - len(files) - 1; at >= 0 && args[at] == "--" {
		return false
	}
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
	for _, name := range []string{"kinds", "min-confidence", "format", "samples", "version"} {
		if strings.HasSuffix(text, ": -"+name) || strings.Contains(text, " for -"+name+":") {
			if strings.HasPrefix(text, "flag needs an argument") {
				return errors.New("embargo: --" + name + " needs a value; see embargo --help")
			}
			return errors.New("embargo: --" + name + " has an invalid value; see embargo --help")
		}
	}
	return errors.New("embargo: unknown flag; the flags are --kinds, --min-confidence, --format, --samples and --version; see embargo --help")
}
