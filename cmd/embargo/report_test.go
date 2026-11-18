package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

const reportPAN = "pan"

func TestReportCountsOffsetsAndNeverEchoesInput(t *testing.T) {
	t.Parallel()
	const pan = "4111111111111111"
	const password = "private-fixture-value"
	input := "受注 ok\r\ncard=" + pan + "\r\npassword=" + password + "\ncard=" + pan
	var output bytes.Buffer
	if err := run([]string{flagFormat, formatJSON}, strings.NewReader(input), &output); err != nil {
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
			if sample.End <= sample.Start {
				t.Fatal("empty sample span")
			}
		}
	}
}

func TestReportSelectionAndSampleLimit(t *testing.T) {
	t.Parallel()
	input := strings.Repeat("card=4111111111111111\n", 10) + "alice@example.com\n"
	var output bytes.Buffer
	if err := run([]string{flagFormat, formatJSON, flagKinds, reportPAN, flagSamples, "1"}, strings.NewReader(input), &output); err != nil {
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
	if err := run([]string{flagFormat, formatJSON, flagKinds, kindsAll}, strings.NewReader("123-45-6789"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "us_ssn") {
		t.Fatal("opt-in kinds missing")
	}
	output.Reset()
	if err := run([]string{flagFormat, formatJSON, flagMinimum, "0.7"}, strings.NewReader("order_id=4111111111111111\n"), &output); err != nil || strings.Contains(output.String(), `"pan"`) {
		t.Fatalf("minimum confidence ignored: %v %s", err, output.String())
	}
}

func TestReportRejectsIncompleteInputAndOutputFailure(t *testing.T) {
	t.Parallel()
	for _, input := range []io.Reader{strings.NewReader(strings.Repeat("x", maximumLine+1)), &failingInput{}} {
		var out bytes.Buffer
		err := run([]string{flagFormat, formatJSON}, input, &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-error") {
			t.Fatal("incomplete report accepted or error echoed")
		}
	}
	if run([]string{flagFormat, formatJSON}, strings.NewReader(""), failingOutput{}) == nil {
		t.Fatal("output failure ignored")
	}
	var out bytes.Buffer
	if err := run([]string{flagFormat, formatJSON}, strings.NewReader(""), &out); err != nil || !json.Valid(out.Bytes()) || !strings.Contains(out.String(), `"findings": []`) {
		t.Fatalf("empty input report = %s, %v", out.String(), err)
	}
}

func TestJSONLPrintsEveryFindingWithoutItsValue(t *testing.T) {
	t.Parallel()
	pan := "4111111111111111"
	input := "clean\r\ncard=" + pan + " again " + pan + "\nmail alice@example.com"
	var out bytes.Buffer
	if err := run([]string{flagFormat, formatJSONL}, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), pan) || strings.Contains(out.String(), "alice") {
		t.Fatal("jsonl echoed a matched value")
	}
	want := `{"kind":"pan","start":12,"end":28,"line":2,"column":5}` + "\n" +
		`{"kind":"pan","start":35,"end":51,"line":2,"column":28}` + "\n" +
		`{"kind":"email","start":57,"end":74,"line":3,"column":5}` + "\n"
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
	out.Reset()
	// No output means nothing was found, so a shell can test for any line.
	if err := run([]string{flagFormat, formatJSONL}, strings.NewReader("clean\nlines\n"), &out); err != nil || out.Len() != 0 {
		t.Fatalf("clean input: err=%v output=%q", err, out.String())
	}
}

func TestJSONLStopsAtFailuresAfterEarlierFindings(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	failing := io.MultiReader(strings.NewReader("card=4111111111111111\n"), &failingInput{})
	err := run([]string{flagFormat, formatJSONL}, failing, &out)
	if err == nil || err.Error() != "embargo: input read failed at line 2; output stops before it" || !strings.Contains(out.String(), `"line":1`) {
		t.Fatalf("read failure: err=%v output=%q", err, out.String())
	}
	if run([]string{flagFormat, formatJSONL}, strings.NewReader("card=4111111111111111\n"), failingOutput{}) == nil {
		t.Fatal("output failure ignored")
	}
	if run([]string{flagFormat, formatJSONL}, strings.NewReader("clean\n"), failingOutput{}) != nil {
		t.Fatal("nothing to write must not fail")
	}
	// One line whose findings overflow the output buffer fails while encoding.
	crowded := strings.Repeat("card=4111111111111111 ", 4096) + "\n"
	if err := run([]string{flagFormat, formatJSONL}, strings.NewReader(crowded), failingOutput{}); err == nil || err.Error() != outputWriteFailed {
		t.Fatalf("buffered output failure: %v", err)
	}
}

func TestJSONLFlushesWhenNoInputIsBuffered(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	reader := &pacedReader{output: &out, lines: []string{"card=4111111111111111\n", "mail alice@example.com\n"}, flushed: nil}
	if err := run([]string{flagFormat, formatJSONL}, reader, &out); err != nil {
		t.Fatal(err)
	}
	if len(reader.flushed) == 0 || !reader.flushed[0] {
		t.Fatalf("the first finding was not written before more input was read: %v", reader.flushed)
	}
	if strings.Count(out.String(), "\n") != 2 {
		t.Fatalf("output %q", out.String())
	}
}

func TestReportCountsLinesWithoutTheEmptyEnd(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]int{"": 0, "a\n": 1, "a\nb": 2, "a\n\n": 2} {
		got, err := collectReport(strings.NewReader(input), embargo.NewScanner(), 1)
		if err != nil || got.Lines != want || got.Bytes != int64(len(input)) {
			t.Errorf("%q: lines=%d bytes=%d err=%v, want %d lines", input, got.Lines, got.Bytes, err, want)
		}
	}
}

func TestReportAndJSONLCountEveryLineOfAnOpenPEMBlock(t *testing.T) {
	t.Parallel()
	input := "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\nplain\n"
	var out bytes.Buffer
	if err := run([]string{flagFormat, formatJSONL}, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"private_key_pem","start":0,"end":27,"line":1,"column":0}` + "\n" +
		`{"kind":"private_key_pem","start":28,"end":60,"line":2,"column":0}` + "\n" +
		`{"kind":"private_key_pem","start":61,"end":86,"line":3,"column":0}` + "\n"
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
	out.Reset()
	if err := run([]string{flagFormat, formatJSON}, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	var got report
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Count != 3 {
		t.Fatalf("report did not count the block lines: %s", out.String())
	}
}
