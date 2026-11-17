package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

const (
	auditSamplesFlag           = "--samples"
	auditPAN                   = "pan"
	auditKindsFlag             = "--kinds"
	auditConfidenceFlag        = "--min-confidence"
	auditCompareFlag           = "--compare"
	auditCompareConfidenceFlag = "--compare-min-confidence"
)

func TestAuditCountsOffsetsAndNeverEchoesInput(t *testing.T) {
	t.Parallel()
	const pan = "4111111111111111"
	const password = "private-fixture-value"
	input := "受注 ok\r\ncard=" + pan + "\r\npassword=" + password + "\ncard=" + pan
	var output bytes.Buffer
	if err := runAudit(nil, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), pan) || strings.Contains(output.String(), password) || strings.Contains(output.String(), "受注") {
		t.Fatal("audit echoed source bytes")
	}
	var got report
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Bytes != int64(len(input)) || got.Lines != 4 || len(got.Findings) != 2 {
		t.Fatalf("unexpected totals: %+v", got)
	}
	for _, kind := range got.Findings {
		if !strings.Contains(kind.DropOption, string(kind.Kind)) {
			t.Fatal("missing kind exclusion recipe")
		}
		if kind.Kind == auditPAN {
			if kind.Count != 2 || len(kind.Samples) != 2 || kind.Samples[0].Start != int64(strings.Index(input, pan)) || kind.Samples[1].Start != int64(strings.LastIndex(input, pan)) || kind.Samples[0].Line != 2 || kind.Samples[0].Column != 5 {
				t.Fatalf("wrong PAN locations: %+v", kind)
			}
		}
		for _, sample := range kind.Samples {
			if sample.Value != "[REDACTED]" || sample.End <= sample.Start {
				t.Fatal("sample not safely masked")
			}
		}
	}
}

func TestAuditSelectionAndSampleLimit(t *testing.T) {
	t.Parallel()
	input := strings.Repeat("card=4111111111111111\n", 10) + "alice@example.com\n"
	var output bytes.Buffer
	if err := runAudit([]string{auditKindsFlag, auditPAN, auditSamplesFlag, "1"}, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var got report
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Count != 10 || len(got.Findings[0].Samples) != 1 {
		t.Fatal("selection or sample cap ignored")
	}
	output.Reset()
	if err := runAudit([]string{"--all"}, strings.NewReader("123-45-6789"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "us_ssn") {
		t.Fatal("opt-in kinds missing")
	}
}

func TestAuditRejectsInvalidConfigurationAndIncompleteInput(t *testing.T) {
	t.Parallel()
	if runAudit([]string{"--help"}, strings.NewReader(""), failingOutput{}) == nil {
		t.Fatal("help output failure ignored")
	}
	for _, args := range [][]string{{auditKindsFlag, "unknown"}, {auditKindsFlag, auditPAN, "--all"}, {auditConfidenceFlag, "NaN"}, {auditConfidenceFlag, "2"}, {auditSamplesFlag, "-1"}, {auditSamplesFlag, "21"}, {"extra"}, {"--unknown"}} {
		var out bytes.Buffer
		if runAudit(args, strings.NewReader("sensitive-input"), &out) == nil || out.Len() != 0 {
			t.Fatal("invalid arguments accepted", args)
		}
	}
	for _, input := range []io.Reader{strings.NewReader(strings.Repeat("x", 4<<20)), failingInput{}} {
		var out bytes.Buffer
		err := runAudit(nil, input, &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-error") {
			t.Fatal("incomplete audit accepted or error echoed")
		}
	}
	if runAudit(nil, strings.NewReader(""), failingOutput{}) == nil {
		t.Fatal("output failure ignored")
	}
}

type failingInput struct{}

func (failingInput) Read([]byte) (int, error) { return 0, errors.New("private-error") }

type failingOutput struct{}

func (failingOutput) Write([]byte) (int, error) { return 0, errors.New("output closed") }

//nolint:govet // Test case fields follow the visible input and expected result order.
func TestCompareSettings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args         []string
		gained, lost string
	}{
		{[]string{auditCompareFlag, auditKindsFlag, auditPAN, auditCompareKindsFlag, "email"}, "email", auditPAN},
		{[]string{auditCompareFlag, auditCompareConfidenceFlag, "0.7"}, "", auditPAN},
		{[]string{auditCompareFlag, auditConfidenceFlag, "0.7"}, auditPAN, ""},
		{[]string{auditCompareFlag}, "", ""},
	} {
		var out bytes.Buffer
		input := "order_id=4111111111111111\nalice@example.com\n"
		if err := runAudit(tc.args, strings.NewReader(input), &out); err != nil {
			t.Fatal(err)
		}
		var got comparisonReport
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		for label, check := range map[string]struct {
			rows []kindReport
			kind string
		}{"gained": {got.Gained, tc.gained}, "lost": {got.Lost, tc.lost}} {
			if check.kind == "" {
				if len(check.rows) != 0 {
					t.Fatalf("unexpected %s: %+v", label, got)
				}
				continue
			}
			if len(check.rows) != 1 || string(check.rows[0].Kind) != check.kind || check.rows[0].Count != 1 || check.rows[0].Samples[0].Value != "[REDACTED]" {
				t.Fatalf("wrong %s: %+v", label, got)
			}
		}
		if got.Before.Bytes != int64(len(input)) || got.After.Bytes != got.Before.Bytes || got.Before.Lines != 2 || got.After.Lines != 2 || strings.Contains(out.String(), "411111") || strings.Contains(out.String(), "alice") {
			t.Fatalf("unsafe/incomplete compare: %s", out.String())
		}
	}
	for _, args := range [][]string{{auditCompareKindsFlag, auditPAN}, {auditCompareFlag, auditCompareKindsFlag, "unknown"}, {auditCompareFlag, "--compare-all", auditCompareKindsFlag, auditPAN}, {auditCompareFlag, auditCompareConfidenceFlag, "NaN"}, {auditCompareFlag, auditCompareConfidenceFlag, "-1"}, {auditCompareFlag, auditCompareConfidenceFlag, "2"}} {
		var out bytes.Buffer
		if runAudit(args, strings.NewReader(""), &out) == nil || out.Len() != 0 {
			t.Fatal("invalid comparison accepted", args)
		}
	}
	var out bytes.Buffer
	if runAudit([]string{auditCompareFlag}, failingInput{}, &out) == nil || out.Len() != 0 {
		t.Fatal("partial comparison escaped")
	}
}

func TestExitStatusAndSafeDiagnostic(t *testing.T) {
	t.Parallel()
	for _, invalid := range []bool{false, true} {
		var output, diagnostic bytes.Buffer
		var args []string
		if invalid {
			args = []string{"--private-unrecognized-flag"}
		}
		code := exitCode(append([]string{"audit"}, args...), strings.NewReader(""), &output, &diagnostic)
		if invalid {
			if code != 1 || output.Len() != 0 || !strings.HasPrefix(diagnostic.String(), "embargo audit:") || strings.Contains(diagnostic.String(), "private-unrecognized") {
				t.Fatal("unsafe command failure")
			}
			if exitCode(append([]string{"audit"}, args...), strings.NewReader(""), &output, failingOutput{}) != 1 {
				t.Fatal("failed diagnostic changed exit status")
			}
		} else if code != 0 || diagnostic.Len() != 0 || !json.Valid(output.Bytes()) {
			t.Fatal("successful command did not return a JSON report")
		}
	}
}

const auditCompareKindsFlag = "--compare-kinds"

func TestAuditHelpAndInvalidFlagUsage(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"-h", "--help", "--unknown=opaqueFixture"} {
		var out, diagnostics bytes.Buffer
		code := exitCode([]string{"audit", arg}, strings.NewReader(""), &out, &diagnostics)
		combined := out.String() + diagnostics.String()
		want := 0
		if strings.Contains(arg, "unknown") {
			want = 1
		}
		if code != want || !strings.Contains(combined, "Usage:") || !strings.Contains(combined, "--kinds") || strings.Contains(combined, "opaqueFixture") {
			t.Errorf("%s: status=%d output=%q", arg, code, combined)
		}
	}
}

const auditSecretFixture = "password=opaqueFixture"

func TestAuditOptionDiagnostics(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		want string
		args []string
	}{
		{args: []string{auditConfidenceFlag, "2"}, want: "embargo audit: --min-confidence must be between 0 and 1\n"},
		{args: []string{auditConfidenceFlag, auditSecretFixture}, want: "embargo audit: --min-confidence must be between 0 and 1\n"},
		{args: []string{auditSamplesFlag, "21"}, want: "embargo audit: --samples must be between 0 and 20\n"},
		{args: []string{auditSamplesFlag, auditSecretFixture}, want: "embargo audit: --samples must be between 0 and 20\n"},
		{args: []string{"--kinds", "xyz"}, want: "embargo audit: --kinds contains an unknown kind; use --help for kinds\n"},
		{args: []string{"--kinds", auditSecretFixture}, want: "embargo audit: --kinds contains an unknown kind; use --help for kinds\n"},
	} {
		var out, diagnostics bytes.Buffer
		code := exitCode(append([]string{"audit"}, tc.args...), strings.NewReader(auditSecretFixture), &out, &diagnostics)
		if code != 1 || out.Len() != 0 || diagnostics.String() != tc.want {
			t.Errorf("exit=%d stdout=%q stderr=%q want=%q", code, out.String(), diagnostics.String(), tc.want)
		}
	}
	for _, args := range [][]string{{auditConfidenceFlag, "0"}, {auditConfidenceFlag, "1"}, {auditSamplesFlag, "0"}, {auditSamplesFlag, "20"}} {
		var out, diagnostics bytes.Buffer
		if code := exitCode(append([]string{"audit"}, args...), strings.NewReader("clean"), &out, &diagnostics); code != 0 || out.Len() == 0 || diagnostics.Len() != 0 {
			t.Errorf("valid boundary rejected: %v", args)
		}
	}
}
