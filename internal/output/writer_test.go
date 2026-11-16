package output

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/nao1215/embargo"
)

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

type panicDetector struct{}

//nolint:govet // Deliberately exercise the panic(nil) compatibility path.
func (panicDetector) Scan([]byte) []embargo.Finding { panic(nil) }

func TestWriterBoundariesAndLifecycle(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds())
	t.Run("exact byte limit", func(t *testing.T) {
		t.Parallel()
		var sink bytes.Buffer
		w := NewWriter(&sink, scanner)
		input := "{\"x\":\"" + strings.Repeat("a", maxEventBytes-len("{\"x\":\"\"}\n")) + "\"}\n"
		if n, err := w.Write([]byte(input)); err != nil || n != len(input) || sink.Len() != len(input) {
			t.Fatal("exact limit rejected")
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(nil); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("closed writer accepted data")
		}
	})
	for _, input := range []string{strings.Repeat(" ", maxEventBytes+1) + "\n", "invalid\n"} {
		t.Run("failure retains next record", func(t *testing.T) {
			t.Parallel()
			var sink bytes.Buffer
			w := NewWriter(&sink, scanner)
			if _, err := w.Write([]byte(input)); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("{}\n")); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(sink.String(), "record withheld") || !strings.HasSuffix(sink.String(), "{}\n") {
				t.Fatal("fallback or later record missing")
			}
		})
	}
	t.Run("short downstream write", func(t *testing.T) {
		t.Parallel()
		w := NewWriter(shortWriter{}, scanner)
		if _, err := w.Write([]byte("{}\n")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatal("short write lost")
		}
	})
	t.Run("empty write and flush", func(t *testing.T) {
		t.Parallel()
		w := NewWriter(io.Discard, scanner)
		if n, err := w.Write(nil); err != nil || n != 0 {
			t.Fatal("empty write failed")
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestWriterConcurrentWholeEvents(t *testing.T) {
	t.Parallel()
	var sink bytes.Buffer
	w := NewWriter(&sink, embargo.NewScanner(embargo.WithKinds(embargo.KindEmail)))
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			if _, err := w.Write([]byte("{\"email\":\"alice@example.com\"}\n")); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Count(sink.String(), "[REDACTED]") != 16 || strings.Contains(sink.String(), "alice") {
		t.Fatal("concurrent event lost or leaked")
	}
}

func TestJSONScannerPanicNilFailsClosed(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_OUTPUT_PANIC_CHILD") == "1" {
		scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(panicDetector{}))
		if data, err := JSON([]byte(`{"value":"public"}`), scanner); err == nil || data != nil {
			t.Fatal("panic(nil) escaped")
		}
		return
	}
	// #nosec G204 G702 -- re-execute this test binary with a fixed test selector.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestJSONScannerPanicNilFailsClosed$")
	cmd.Env = append(os.Environ(), "GODEBUG=panicnil=1", "EMBARGO_OUTPUT_PANIC_CHILD=1")
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child failed: %v %s", err, data)
	}
}

func TestWriterRequiresDependencies(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		writer  io.Writer
		scanner *embargo.Scanner
		name    string
	}{
		{name: "nil writer", scanner: embargo.NewScanner()},
		{name: "typed nil writer", writer: (*bytes.Buffer)(nil), scanner: embargo.NewScanner()},
		{name: "nil scanner", writer: io.Discard},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() != "embargo: nil logger adapter dependency" {
					t.Error("missing fixed dependency panic")
				}
			}()
			NewWriter(tc.writer, tc.scanner)
		})
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

func TestDiagnosticFlushPreservesSinkFailure(t *testing.T) {
	t.Parallel()
	for _, input := range []string{`{"planted-key":"planted-value`, strings.Repeat("x", maxEventBytes+1)} {
		t.Run("pending diagnostic fails at sink", func(t *testing.T) {
			t.Parallel()
			writer := NewWriter(failedWriter{}, embargo.NewScanner())
			if _, err := writer.Write([]byte(input)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Flush(); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("diagnostic sink failure lost: %v", err)
			}
			if n, err := writer.Write([]byte("{}\n")); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("sink failure did not stop later writes")
			}
			if err := writer.Close(); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("close lost diagnostic sink failure")
			}
		})
	}
}
