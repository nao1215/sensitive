package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

const reportPAN = "pan"

func TestReportCountsOffsetsAndNeverEchoesInput(t *testing.T) {
	t.Parallel()
	const pan = "4111111111111111"
	const password = "private-fixture-value"
	input := "受注 ok\r\ncard=" + pan + "\r\npassword=" + password + "\ncard=" + pan
	var output bytes.Buffer
	if err := run([]string{"--report"}, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), pan) || strings.Contains(output.String(), password) || strings.Contains(output.String(), "受注") {
		t.Fatal("report echoed source bytes")
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
		if kind.Kind == reportPAN {
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

func TestReportSelectionAndSampleLimit(t *testing.T) {
	t.Parallel()
	input := strings.Repeat("card=4111111111111111\n", 10) + "alice@example.com\n"
	var output bytes.Buffer
	if err := run([]string{"--report", "--kinds", reportPAN, "--samples", "1"}, strings.NewReader(input), &output); err != nil {
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
	if err := run([]string{"--report", "--kinds", "all"}, strings.NewReader("123-45-6789"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "us_ssn") {
		t.Fatal("opt-in kinds missing")
	}
	output.Reset()
	if err := run([]string{"--report", "--min-confidence", "0.7"}, strings.NewReader("order_id=4111111111111111\n"), &output); err != nil || strings.Contains(output.String(), `"pan"`) {
		t.Fatalf("minimum confidence ignored: %v %s", err, output.String())
	}
}

func TestReportRejectsIncompleteInputAndOutputFailure(t *testing.T) {
	t.Parallel()
	for _, input := range []io.Reader{strings.NewReader(strings.Repeat("x", 4<<20)), failingInput{}} {
		var out bytes.Buffer
		err := run([]string{"--report"}, input, &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-error") {
			t.Fatal("incomplete report accepted or error echoed")
		}
	}
	if run([]string{"--report"}, strings.NewReader(""), failingOutput{}) == nil {
		t.Fatal("output failure ignored")
	}
	var out bytes.Buffer
	if err := run([]string{"--report"}, strings.NewReader(""), &out); err != nil || !json.Valid(out.Bytes()) || !strings.Contains(out.String(), `"findings": []`) {
		t.Fatalf("empty input report = %s, %v", out.String(), err)
	}
}
