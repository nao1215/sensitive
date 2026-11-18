package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

const (
	filterPAN      = "4111111111111111"
	filterEmail    = "alice@example.com"
	filterPassword = "private-fixture-value"
	filterMarker   = "[REDACTED]"
)

func TestFilterMasksTextAndJSONLinesAndKeepsEndings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, input, want string
	}{
		{"text line keeps its context", "login " + filterEmail + " ok\n", "login " + filterMarker + " ok\n"},
		{"CRLF ending is kept", "card=" + filterPAN + "\r\n", "card=" + filterMarker + "\r\n"},
		{"final line without newline stays without one", "last " + filterPAN, "last " + filterMarker},
		{"JSON object keeps keys and the sensitive key rule", `{"password":"` + filterPassword + `","n": 1}` + "\n", `{"password":"[REDACTED]","n":1}` + "\n"},
		{"JSON array is masked by value", `  ["` + filterEmail + `"]` + "\n", `["[REDACTED]"]` + "\n"},
		{"invalid JSON falls back to text", `{"card":"` + filterPAN + "\n", `{"card":"` + filterMarker + "\n"},
		{"empty lines pass through", "\n\r\n", "\n\r\n"},
		{"clean text is unchanged", "plain words\n", "plain words\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			if err := run(nil, strings.NewReader(tt.input), &out); err != nil {
				t.Fatal(err)
			}
			if out.String() != tt.want {
				t.Fatalf("got %q, want %q", out.String(), tt.want)
			}
		})
	}
}

func TestFilterKindSelection(t *testing.T) {
	t.Parallel()
	input := filterEmail + " " + filterPAN + "\n"
	for _, tc := range []struct {
		want string
		args []string
	}{
		{args: []string{flagKinds, "pan"}, want: filterEmail + " " + filterMarker + "\n"},
		{args: []string{flagKinds, "email"}, want: filterMarker + " " + filterPAN + "\n"},
		{args: []string{flagMinimum, "1"}, want: filterMarker + " " + filterMarker + "\n"},
		{args: []string{flagKinds, kindsAll}, want: filterMarker + " " + filterMarker + "\n"},
	} {
		var out bytes.Buffer
		if err := run(tc.args, strings.NewReader(input), &out); err != nil {
			t.Fatal(tc.args, err)
		}
		if out.String() != tc.want {
			t.Errorf("%v: got %q, want %q", tc.args, out.String(), tc.want)
		}
	}
}

func TestFilterStopsBeforeOverlongLineAndReadFailure(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	input := "first " + filterPAN + "\n" + strings.Repeat("x", maximumLine+1) + "\nnever written\n"
	err := run(nil, strings.NewReader(input), &out)
	if err == nil || err.Error() != "embargo: line 2 exceeds the 4 MiB limit; output stops before it" {
		t.Fatalf("over-long line: %v", err)
	}
	if out.String() != "first "+filterMarker+"\n" {
		t.Fatalf("output before the failure = %q", out.String())
	}
	out.Reset()
	exact := strings.Repeat("y", maximumLine-1) + "\n"
	if exactErr := run(nil, strings.NewReader(exact), &out); exactErr != nil || out.Len() != len(exact) {
		t.Fatalf("line at the limit: err=%v length=%d", exactErr, out.Len())
	}
	out.Reset()
	failing := io.MultiReader(strings.NewReader("card="+filterPAN+"\n"), &failingInput{})
	err = run(nil, failing, &out)
	if err == nil || err.Error() != "embargo: input read failed at line 2; output stops before it" || strings.Contains(out.String(), filterPAN) {
		t.Fatalf("read failure: err=%v output=%q", err, out.String())
	}
}

func TestFilterReportsOutputFailures(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"line\n", "a\n" + strings.Repeat("z", maximumLine+1)} {
		if err := run(nil, strings.NewReader(input), failingOutput{}); err == nil || err.Error() != outputWriteFailed {
			t.Errorf("output failure for %d bytes: %v", len(input), err)
		}
	}
	// A line larger than the output buffer reaches the writer before the flush.
	if err := run(nil, strings.NewReader(strings.Repeat("w", 2*ioBuffer)+"\n"), &shortWriter{limit: 0}); err == nil || err.Error() != outputWriteFailed {
		t.Errorf("failure writing a large line: %v", err)
	}
}

// shortWriter accepts limit bytes and then fails, like a closed pipe.
type shortWriter struct{ limit int }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		w.limit = 0
		return 0, errors.New("pipe closed")
	}
	w.limit -= len(p)
	return len(p), nil
}

func TestReadLineAndSplitEnding(t *testing.T) {
	t.Parallel()
	body, ending := splitEnding([]byte("a\r\n"))
	if string(body) != "a" || string(ending) != "\r\n" {
		t.Fatalf("CRLF split = %q %q", body, ending)
	}
	body, ending = splitEnding([]byte("\r\n"))
	if len(body) != 0 || string(ending) != "\r\n" {
		t.Fatalf("bare CRLF split = %q %q", body, ending)
	}
	body, ending = splitEnding([]byte("\n"))
	if len(body) != 0 || string(ending) != "\n" {
		t.Fatalf("LF split = %q %q", body, ending)
	}
	body, ending = splitEnding([]byte("tail\r"))
	if string(body) != "tail\r" || ending != nil {
		t.Fatalf("unterminated split = %q %q", body, ending)
	}
}

// pacedReader hands out one line per Read and records, on the next Read,
// whether the previous line had already reached the output.
type pacedReader struct {
	output  *bytes.Buffer
	lines   []string
	flushed []bool
}

func (r *pacedReader) Read(p []byte) (int, error) {
	if len(r.flushed) > 0 || len(r.lines) < 2 {
		r.flushed = append(r.flushed, r.output.Len() > 0)
	}
	if len(r.lines) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.lines[0])
	r.lines = r.lines[1:]
	return n, nil
}

func TestFilterFlushesWhenNoInputIsBuffered(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	reader := &pacedReader{output: &out, lines: []string{"first\n", "second\n"}, flushed: nil}
	if err := run(nil, reader, &out); err != nil {
		t.Fatal(err)
	}
	if len(reader.flushed) == 0 || !reader.flushed[0] {
		t.Fatalf("the first line was not written before more input was read: %v", reader.flushed)
	}
	if out.String() != "first\nsecond\n" {
		t.Fatalf("output %q", out.String())
	}
}

func TestFilterPassesBinaryBytesAndMasksLongJSONAsText(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	binary := "nul\x00 " + filterPAN + " \xff\xfe end\n"
	if err := run(nil, strings.NewReader(binary), &out); err != nil || out.String() != "nul\x00 "+filterMarker+" \xff\xfe end\n" {
		t.Fatalf("binary line: err=%v output=%q", err, out.String())
	}
	out.Reset()
	// MaskJSON accepts at most 1 MiB, so a longer JSON line is masked as text
	// and keeps its original spacing.
	long := `{"card": "` + filterPAN + `", "pad": "` + strings.Repeat("p", 1<<20) + `"}` + "\n"
	want := `{"card": "` + filterMarker + `", "pad": "` + strings.Repeat("p", 1<<20) + `"}` + "\n"
	if err := run(nil, strings.NewReader(long), &out); err != nil || out.String() != want {
		t.Fatalf("long JSON line: err=%v length=%d", err, out.Len())
	}
}

func TestFilterAndReportShareTheLineLimit(t *testing.T) {
	t.Parallel()
	exact := strings.Repeat("z", maximumLine)
	over := exact + "z"
	for _, args := range [][]string{nil, {flagFormat, formatJSON}} {
		var out bytes.Buffer
		if err := run(args, strings.NewReader(exact), &out); err != nil {
			t.Errorf("%v: a final line of exactly 4 MiB was rejected: %v", args, err)
		}
		out.Reset()
		err := run(args, strings.NewReader("ok\n"+over), &out)
		if err == nil || !strings.HasPrefix(err.Error(), "embargo: line 2 exceeds the 4 MiB limit; ") {
			t.Errorf("%v: over-long line: %v", args, err)
		}
	}
}
