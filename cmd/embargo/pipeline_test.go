package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/embargo"
)

// lineByLine returns a reader that hands out one line per Read, so every
// line is a batch of its own and every block crosses a batch boundary.
func lineByLine(text string) io.Reader {
	lines := strings.SplitAfter(text, "\n")
	chunks := make([]io.Reader, 0, len(lines))
	for _, line := range lines {
		if line != "" {
			chunks = append(chunks, strings.NewReader(line))
		}
	}
	return &oneChunkReader{chunks: chunks}
}

func TestBatchesMaskLikeOneBatch(t *testing.T) {
	t.Parallel()
	inputs := map[string]struct {
		mode string
		text string
	}{
		"pem":  {inputLines, "before\n-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END PRIVATE KEY-----\nafter " + filterEmail + "\n"},
		"json": {inputLines, "{\n  \"token\":\n    \"opaque\",\n  \"secret\": [\n    \"one\"\n  ]\n}\n{\"pass\":\"x\"}\n"},
		"yaml": {inputLines, "password: |\n  first\n  second\nuser: bob\n"},
		"csv":  {inputCSV, "id,secret\n1,\"a\nb\"\n2,c\nid,secret\n3,d\n"},
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			scanner := embargo.NewScanner()
			var whole, split bytes.Buffer
			if err := filterLines(strings.NewReader(input.text), &whole, newLineScanner(scanner, input.mode)); err != nil {
				t.Fatal(err)
			}
			if err := filterLines(lineByLine(input.text), &split, newLineScanner(scanner, input.mode)); err != nil {
				t.Fatal(err)
			}
			if split.String() != whole.String() || whole.String() == input.text {
				t.Fatalf("line by line\n%s\none batch\n%s", split.String(), whole.String())
			}
			var wholeReport, splitReport bytes.Buffer
			if err := writeFindings(strings.NewReader(input.text), &wholeReport, newLineScanner(scanner, input.mode)); err != nil {
				t.Fatal(err)
			}
			if err := writeFindings(lineByLine(input.text), &splitReport, newLineScanner(scanner, input.mode)); err != nil {
				t.Fatal(err)
			}
			if splitReport.String() != wholeReport.String() || wholeReport.Len() == 0 {
				t.Fatalf("line by line\n%s\none batch\n%s", splitReport.String(), wholeReport.String())
			}
		})
	}
}

func TestABlockAcrossTheBatchSizeIsScannedAgain(t *testing.T) {
	t.Parallel()
	// The block's first line ends the first batch, which batchBytes cuts.
	filler := func(rest int) string { return strings.Repeat("f", batchBytes-rest-1) + "\n" }
	yamlFiller, csvFiller := filler(len("password: |\n")), filler(len("secret\n\"a\n"))
	for _, tc := range []struct{ mode, text, want string }{
		{inputLines, yamlFiller + "password: |\n  first\n", yamlFiller + "password: " + filterMarker + "\n  " + filterMarker + "\n"},
		{inputCSV, "secret\n" + csvFiller + "\"a\nb\"\n", "secret\n" + filterMarker + "\n\"" + filterMarker + "\n" + filterMarker + "\"\n"},
	} {
		var out bytes.Buffer
		if err := filterLines(strings.NewReader(tc.text), &out, newLineScanner(embargo.NewScanner(), tc.mode)); err != nil {
			t.Fatal(err)
		}
		if out.String() != tc.want {
			t.Fatalf("%s: the end differs: %q", tc.mode, out.String()[max(0, out.Len()-80):])
		}
	}
	lines := strings.Repeat(strings.Repeat("f", 99)+"\n", batchBytes/100+1)
	counted, err := collectReport(strings.NewReader(lines+"x\n"), newLineScanner(embargo.NewScanner(), inputLines), 1)
	if err != nil || counted.Lines != batchBytes/100+2 || counted.Bytes != int64(len(lines)+2) {
		t.Fatalf("report over batches: %+v, %v", counted, err)
	}
}

// blockingReader gives one line and then blocks, as a quiet pipe does.
type blockingReader struct {
	release chan struct{}
	line    string
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if r.line != "" {
		n := copy(p, r.line)
		r.line = ""
		return n, nil
	}
	<-r.release
	return 0, io.EOF
}

func TestAFailedOutputEndsWithoutWaitingForInput(t *testing.T) {
	t.Parallel()
	input := &blockingReader{release: make(chan struct{}), line: "card=" + filterPAN + "\n"}
	defer close(input.release)
	source, closeAll := openInputs(nil, input)
	finished := make(chan error, 1)
	go func() {
		finished <- filterLines(source, failingOutput{}, newLineScanner(embargo.NewScanner(), inputLines))
		closeAll()
	}()
	select {
	case err := <-finished:
		if err == nil || errors.Is(err, errOutputClosed) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the filter waited for input after the output failed")
	}
}

func TestClosedInputsEndTheSequence(t *testing.T) {
	t.Parallel()
	source, closeAll := openInputs(nil, strings.NewReader("a\n"))
	closeAll()
	if n, err := source.Read(make([]byte, 8)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after close = %d, %v", n, err)
	}
}

func TestFillCutsABatchAtTheBatchSize(t *testing.T) {
	t.Parallel()
	line := strings.Repeat("f", 99) + "\n"
	text := strings.Repeat(line, batchBytes/len(line)) + strings.Repeat("g", batchBytes%len(line)-1) + "\n" + "next\n"
	p := &pipeline{base: newLineScanner(embargo.NewScanner(), inputLines), render: renderMasked, consequence: "", lines: 0, size: 0}
	b := &batch{first: 1, done: make(chan struct{})}
	if done := p.fill(bufio.NewReaderSize(strings.NewReader(text), readBuffer), b); done || len(b.data) != batchBytes || b.flush {
		t.Fatalf("batch of %d bytes, done %v, flush %v; want %d", len(b.data), done, b.flush, batchBytes)
	}
}

func TestATableBaseKeepsTheHeader(t *testing.T) {
	t.Parallel()
	base := newLineScanner(embargo.NewScanner(), inputCSV)
	if err := filterLines(strings.NewReader("id,secret\n1,x\n"), io.Discard, base); err != nil {
		t.Fatal(err)
	}
	if strings.Join(base.table.header, ",") != "id,secret" {
		t.Fatalf("base header %q", base.table.header)
	}
}

func TestSendStopsWhenTheWriterHasQuit(t *testing.T) {
	t.Parallel()
	quit := make(chan struct{})
	close(quit)
	if send(make(chan *batch), &batch{}, quit) {
		t.Fatal("send waited for a writer that had quit")
	}
	open := make(chan *batch, 1)
	if !send(open, &batch{}, make(chan struct{})) || len(open) != 1 {
		t.Fatal("send did not deliver the batch")
	}
}
