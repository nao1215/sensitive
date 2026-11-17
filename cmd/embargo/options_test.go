package main

import (
	"bytes"
	"strings"
	"testing"
)

const secretArgument = "password=opaqueFixture"

func TestOptionErrorsNameTheFlagAndNeverEchoTheValue(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		want string
		args []string
	}{
		{args: []string{"--min-confidence", "2"}, want: "embargo: --min-confidence must be a number from 0 to 1"},
		{args: []string{"--min-confidence", "-0.1"}, want: "embargo: --min-confidence must be a number from 0 to 1"},
		{args: []string{"--min-confidence", "NaN"}, want: "embargo: --min-confidence must be a number from 0 to 1"},
		{args: []string{"--min-confidence", secretArgument}, want: "embargo: --min-confidence must be a number from 0 to 1"},
		{args: []string{"--report", "--samples", "21"}, want: "embargo: --samples must be an integer from 0 to 20"},
		{args: []string{"--report", "--samples", "-1"}, want: "embargo: --samples must be an integer from 0 to 20"},
		{args: []string{"--report", "--samples", secretArgument}, want: "embargo: --samples must be an integer from 0 to 20"},
		{args: []string{"--samples", "1"}, want: "embargo: --samples requires --report"},
		{args: []string{"--kinds", "xyz"}, want: "embargo: --kinds must be all or a comma-separated list of kinds; see embargo --help"},
		{args: []string{"--kinds", secretArgument}, want: "embargo: --kinds must be all or a comma-separated list of kinds; see embargo --help"},
		{args: []string{"--kinds", "pan," + secretArgument}, want: "embargo: --kinds must be all or a comma-separated list of kinds; see embargo --help"},
		{args: []string{"--" + secretArgument}, want: "embargo: unknown flag or missing flag value; see embargo --help"},
		{args: []string{"--kinds"}, want: "embargo: unknown flag or missing flag value; see embargo --help"},
		{args: []string{"--all"}, want: "embargo: unknown flag or missing flag value; see embargo --help"},
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
	for _, args := range [][]string{{"--min-confidence", "0"}, {"--min-confidence", "1"}, {"--report", "--samples", "0"}, {"--report", "--samples", "20"}, {"--kinds", "all"}, {"--kinds", " pan , email "}} {
		var out, diagnostics bytes.Buffer
		if code := exitCode(args, strings.NewReader("clean\n"), &out, &diagnostics); code != 0 || out.Len() == 0 || diagnostics.Len() != 0 {
			t.Errorf("valid options rejected: %v stderr=%q", args, diagnostics.String())
		}
	}
	parsed, err := parseOptions([]string{"--report", "a.log", "b.log"})
	if err != nil || !parsed.report || parsed.samples != defaultSamples || parsed.minimum != 0 || strings.Join(parsed.files, ",") != "a.log,b.log" {
		t.Fatalf("parsed = %+v, %v", parsed, err)
	}
}
