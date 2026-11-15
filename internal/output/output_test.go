package output

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestJSONMasksDecodedKeysValuesAndNumbers(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	got, err := JSON([]byte(`{"alice\u0040example.com":["alice\u0040example.com",4111111111111111,{"ok":true}],"x":null,"x":"clean"}`), scanner)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"[REDACTED]\":[\"[REDACTED]\",\"[REDACTED]\",{\"ok\":true}],\"x\":null,\"x\":\"clean\"}\n"
	if string(got) != want {
		t.Fatalf("unexpected sanitized structure: %s", got)
	}
}

func TestWriterBuffersAndRejectsIncompleteOutput(t *testing.T) {
	t.Parallel()
	var sink bytes.Buffer
	w := NewWriter(&sink, embargo.NewScanner(embargo.WithKinds(embargo.KindEmail)))
	if _, err := w.Write([]byte(`{"email":"alice@`)); err != nil {
		t.Fatal(err)
	}
	if sink.Len() != 0 {
		t.Fatal("partial event escaped")
	}
	if _, err := w.Write([]byte("example.com\"}\n")); err != nil {
		t.Fatal(err)
	}
	if sink.String() != "{\"email\":\"[REDACTED]\"}\n" {
		t.Fatal("event not masked")
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"unfinished":`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err == nil {
		t.Fatal("incomplete event accepted")
	}
	if _, err := w.Write([]byte("false}\n")); err == nil {
		t.Fatal("closed writer accepted output")
	}
}

func TestJSONRejectsMalformedOversizedAndDeepInput(t *testing.T) {
	t.Parallel()
	for _, input := range []string{`{"x":`, `[]`, strings.Repeat(" ", 1<<20) + "{}", `{"x":1} {"y":2}`, "{\"x\":\"" + strings.Repeat("a", 1<<20) + "\"}", `{"x":` + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "}"} {
		if got, err := JSON([]byte(input), embargo.NewScanner()); err == nil || got != nil {
			t.Fatal("invalid event escaped")
		}
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriterPreservesSinkErrors(t *testing.T) {
	t.Parallel()
	w := NewWriter(failedWriter{}, embargo.NewScanner())
	if _, err := w.Write([]byte("{\"ok\":true}\n")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("sink error lost")
	}
	if err := w.Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("failure not sticky")
	}
}

func TestJSONUsesFieldNamesForContextDetectors(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCVV, embargo.KindCardExpiry, embargo.KindBankAccount))
	got, err := JSON([]byte(`{"cvv":123,"expiry":"12/28","bank account":"12345678","nested":{"cvv":["456",789]}}`), scanner)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{\"cvv\":\"[REDACTED]\",\"expiry\":\"[REDACTED]\",\"bank account\":\"[REDACTED]\",\"nested\":{\"cvv\":[\"[REDACTED]\",\"[REDACTED]\"]}}\n" {
		t.Fatal("field context was lost")
	}
}

func TestJSONOutputLimitIncludesTerminatingNewline(t *testing.T) {
	t.Parallel()
	// A custom formatter need not terminate its object; JSON adds that byte.
	input := []byte(`{"x":"` + strings.Repeat("a", maxEventBytes-len(`{"x":""}`)) + `"}`)
	if data, err := JSON(input, embargo.NewScanner(embargo.WithKinds())); err == nil || data != nil {
		t.Fatal("output exceeded the complete event byte limit")
	}
}
