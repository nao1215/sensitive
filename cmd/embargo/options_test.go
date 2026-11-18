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
	flagReport         = "--report"
	kindsAll           = "all"
	unknownFlagMessage = "embargo: unknown flag or missing flag value; see embargo --help"
	minimumMessage     = "embargo: --min-confidence must be a number from 0 to 1"
	kindsMessage       = "embargo: --kinds must be all or a comma-separated list of kinds; see embargo --help"
	flagSamples        = "--samples"
	samplesMessage     = "embargo: --samples must be an integer from 0 to 20"
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
		{args: []string{flagReport, flagSamples, "21"}, want: samplesMessage},
		{args: []string{flagReport, flagSamples, "-1"}, want: samplesMessage},
		{args: []string{flagReport, flagSamples, secretArgument}, want: samplesMessage},
		{args: []string{flagSamples, "1"}, want: "embargo: --samples requires --report"},
		{args: []string{flagKinds, "xyz"}, want: kindsMessage},
		{args: []string{flagKinds, secretArgument}, want: kindsMessage},
		{args: []string{flagKinds, "pan," + secretArgument}, want: kindsMessage},
		{args: []string{"--" + secretArgument}, want: unknownFlagMessage},
		{args: []string{flagKinds}, want: unknownFlagMessage},
		{args: []string{"--all"}, want: unknownFlagMessage},
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
	for _, args := range [][]string{{flagMinimum, "0"}, {flagMinimum, "1"}, {flagReport, flagSamples, "0"}, {flagReport, flagSamples, "20"}, {flagKinds, kindsAll}, {flagKinds, " pan , email "}} {
		var out, diagnostics bytes.Buffer
		if code := exitCode(args, strings.NewReader("clean\n"), &out, &diagnostics); code != 0 || out.Len() == 0 || diagnostics.Len() != 0 {
			t.Errorf("valid options rejected: %v stderr=%q", args, diagnostics.String())
		}
	}
	parsed, err := parseOptions([]string{flagReport, fileArgument, "b.log"})
	if err != nil || !parsed.report || parsed.samples != defaultSamples || parsed.minimum != 0 || strings.Join(parsed.files, ",") != "a.log,b.log" {
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
	for _, args := range [][]string{{fileArgument, flagKinds, "email"}, {fileArgument, "-x"}, {fileArgument, flagReport}} {
		var out, diagnostics bytes.Buffer
		code := exitCode(args, strings.NewReader(""), &out, &diagnostics)
		if code != 1 || out.Len() != 0 || diagnostics.String() != "embargo: flags must come before the files; see embargo --help\n" {
			t.Errorf("%v: exit=%d stdout=%q stderr=%q", args, code, out.String(), diagnostics.String())
		}
	}
	for _, args := range [][]string{{"--", "-x.log"}, {flagReport, "--", "-", "-y"}, {"-"}} {
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
