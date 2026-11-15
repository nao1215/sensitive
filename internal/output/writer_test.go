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
	t.Run("overflow is sticky", func(t *testing.T) {
		t.Parallel()
		var sink bytes.Buffer
		w := NewWriter(&sink, scanner)
		if _, err := w.Write([]byte(strings.Repeat(" ", maxEventBytes+1))); err == nil {
			t.Fatal("overflow accepted")
		}
		if _, err := w.Write([]byte("{}\n")); err == nil || sink.Len() != 0 {
			t.Fatal("failed writer forwarded bytes")
		}
	})
	t.Run("malformed is sticky", func(t *testing.T) {
		t.Parallel()
		var sink bytes.Buffer
		w := NewWriter(&sink, scanner)
		if _, err := w.Write([]byte("invalid\n")); err == nil {
			t.Fatal("malformed JSON accepted")
		}
		if _, err := w.Write([]byte("{}\n")); err == nil || sink.Len() != 0 {
			t.Fatal("failed writer forwarded bytes")
		}
	})
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
