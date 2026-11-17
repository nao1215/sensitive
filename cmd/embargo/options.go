package main

import (
	"errors"
	"flag"
	"io"
	"strconv"
)

const (
	usage = `Usage: embargo [--kinds all|KIND,...] [--min-confidence 0] [--report [--samples 3]] [file ...]

Masks secrets and personal data in each line of the files, or of stdin, and writes the lines to stdout.
A line holding one JSON object or array keeps its keys, types and nesting and is written compact.
Lines keep their endings. A read failure or a line longer than 4 MiB stops the output with an error.

  --kinds KIND,...      detect only these kinds; all selects every kind (default: the 25 default kinds)
  --min-confidence N    drop findings below N, from 0 to 1 (default 0)
  --report              print per-kind counts and masked byte locations as JSON instead of masked lines
  --samples N           locations per kind in the report, from 0 to 20 (default 3; needs --report)
  --version             print the version
`
	maximumSamples = 20
	defaultSamples = 3
)

// options is the decoded and validated command line.
type options struct {
	kinds   string
	files   []string
	minimum float64
	samples int
	report  bool
	version bool
}

// parseOptions decodes flags with the standard flag package. Errors name the
// flag and its allowed values but never repeat what was passed.
func parseOptions(args []string) (*options, error) {
	parsed := &options{kinds: "", files: nil, minimum: 0, samples: defaultSamples, report: false, version: false}
	var minimumText, samplesText string
	flags := flag.NewFlagSet("embargo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&parsed.kinds, "kinds", "", "")
	flags.StringVar(&minimumText, "min-confidence", "0", "")
	flags.BoolVar(&parsed.report, "report", false, "")
	flags.StringVar(&samplesText, "samples", strconv.Itoa(defaultSamples), "")
	flags.BoolVar(&parsed.version, "version", false, "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, errors.New("embargo: unknown flag or missing flag value; see embargo --help")
	}
	minimum, ok := parseConfidence(minimumText)
	if !ok {
		return nil, errors.New("embargo: --min-confidence must be a number from 0 to 1")
	}
	samples, err := strconv.Atoi(samplesText)
	if err != nil || samples < 0 || samples > maximumSamples {
		return nil, errors.New("embargo: --samples must be an integer from 0 to 20")
	}
	samplesSet := false
	flags.Visit(func(f *flag.Flag) { samplesSet = samplesSet || f.Name == "samples" })
	if samplesSet && !parsed.report {
		return nil, errors.New("embargo: --samples requires --report")
	}
	parsed.minimum, parsed.samples, parsed.files = minimum, samples, flags.Args()
	return parsed, nil
}
