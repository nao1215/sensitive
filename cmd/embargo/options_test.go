package main

import (
	"bytes"
	"strings"
	"testing"
)

const (
	fileArgument       = "a.log"
	secretArgument     = "password=opaqueFixture"
	flagKinds          = "--kinds"
	flagMinimum        = "--min-confidence"
	flagFormat         = "--format"
	kindsAll           = "all"
	unknownFlagMessage = "embargo: unknown flag; the flags are --kinds, --min-confidence, --format, --samples and --version; see embargo --help"
	minimumMessage     = "embargo: --min-confidence must be a number from 0 to 1"
	kindsMessage       = "embargo: --kinds must be all or a comma-separated list of kinds; see embargo --help"
	flagSamples        = "--samples"
	samplesMessage     = "embargo: --samples must be an integer from 0 to 20"
	formatMessage      = "embargo: --format must be text, json or jsonl"
)

func TestOptionErrorsNameTheFlagAndNeverEchoTheValue(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		want string
		args []string
	}{
		{args: []string{flagMinimum, "2"}, want: minimumMessage},
		{args: []string{flagMinimum, "-0.1"}, want: minimumMessage},
		{args: []string{flagMinimum, "NaN"}, want: minimumMessage},
		{args: []string{flagMinimum, secretArgument}, want: minimumMessage},
		{args: []string{flagFormat, formatJSON, flagSamples, "21"}, want: samplesMessage},
		{args: []string{flagFormat, formatJSON, flagSamples, "-1"}, want: samplesMessage},
		{args: []string{flagFormat, formatJSON, flagSamples, secretArgument}, want: samplesMessage},
		{args: []string{flagSamples, "1"}, want: "embargo: --samples requires --format json"},
		{args: []string{flagKinds, "xyz"}, want: kindsMessage},
		{args: []string{flagKinds, secretArgument}, want: kindsMessage},
		{args: []string{flagKinds, "pan," + secretArgument}, want: kindsMessage},
		{args: []string{"--" + secretArgument}, want: unknownFlagMessage},
		{args: []string{flagKinds}, want: "embargo: --kinds needs a value; see embargo --help"},
		{args: []string{"--version=maybe"}, want: "embargo: --version has an invalid value; see embargo --help"},
		{args: []string{flagKinds, "emial"}, want: "embargo: --kinds must be all or a comma-separated list of kinds; unknown kind \"emial\" (did you mean \"email\"?); see embargo --help"},
		{args: []string{"--all"}, want: unknownFlagMessage},
		{args: []string{"--report"}, want: unknownFlagMessage},
		{args: []string{flagFormat, "yaml"}, want: formatMessage},
		{args: []string{flagFormat, secretArgument}, want: formatMessage},
		{args: []string{flagFormat, formatJSONL, flagSamples, "1"}, want: "embargo: --samples requires --format json"},
	} {
		var out, diagnostics bytes.Buffer
		code := exitCode(tc.args, strings.NewReader(secretArgument), &out, &diagnostics)
		if code != 1 || out.Len() != 0 || diagnostics.String() != tc.want+"\n" || strings.Contains(diagnostics.String(), "opaqueFixture") {
			t.Errorf("%v: exit=%d stdout=%q stderr=%q", tc.args, code, out.String(), diagnostics.String())
		}
	}
}

func TestOptionBoundariesAreAccepted(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{flagMinimum, "0"}, {flagMinimum, "1"}, {flagFormat, formatJSON, flagSamples, "0"}, {flagFormat, formatJSON, flagSamples, "20"}, {flagKinds, kindsAll}, {flagKinds, " pan , email "}} {
		var out, diagnostics bytes.Buffer
		if code := exitCode(args, strings.NewReader("clean\n"), &out, &diagnostics); code != 0 || out.Len() == 0 || diagnostics.Len() != 0 {
			t.Errorf("valid options rejected: %v stderr=%q", args, diagnostics.String())
		}
	}
	parsed, err := parseOptions([]string{flagFormat, formatJSON, fileArgument, "b.log"})
	if err != nil || parsed.format != formatJSON || parsed.samples != defaultSamples || parsed.minimum != 0 || strings.Join(parsed.files, ",") != "a.log,b.log" {
		t.Fatalf("parsed = %+v, %v", parsed, err)
	}
}

func TestParseConfidenceBounds(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]bool{"0": true, "1": true, "0.5": true, "-0.01": false, "1.01": false, "NaN": false, "high": false} {
		if _, ok := parseConfidence(text); ok != want {
			t.Errorf("parseConfidence(%q) ok = %v, want %v", text, ok, want)
		}
	}
}

func TestFlagsAfterFilesAreRejected(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{fileArgument, flagKinds, "email"}, {fileArgument, "-x"}, {fileArgument, flagFormat, formatJSON}} {
		var out, diagnostics bytes.Buffer
		code := exitCode(args, strings.NewReader(""), &out, &diagnostics)
		if code != 1 || out.Len() != 0 || diagnostics.String() != "embargo: flags must come before the files; see embargo --help\n" {
			t.Errorf("%v: exit=%d stdout=%q stderr=%q", args, code, out.String(), diagnostics.String())
		}
	}
	for _, args := range [][]string{{"--", "-x.log"}, {flagFormat, formatJSON, "--", "-", "-y"}, {"-"}} {
		parsed, err := parseOptions(args)
		if err != nil {
			t.Errorf("%v: %v", args, err)
			continue
		}
		if want := args[len(args)-len(parsed.files):]; strings.Join(parsed.files, ",") != strings.Join(want, ",") {
			t.Errorf("%v: files %v", args, parsed.files)
		}
	}
}
