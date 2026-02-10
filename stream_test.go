package sensitive_test

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/nao1215/sensitive"
	"github.com/nao1215/sensitive/detector"
)

func TestScanner_ScanReader(t *testing.T) {
	t.Parallel()

	t.Run("detects sensitive data from reader", func(t *testing.T) {
		t.Parallel()

		scanner := sensitive.NewScanner(sensitive.WithEmail())
		r := strings.NewReader("contact: tanaka@example.com")

		findings, err := scanner.ScanReader(r)
		if err != nil {
			t.Fatalf("ScanReader returned error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if !findings[0].IsEmail() {
			t.Error("expected email finding")
		}
	})

	t.Run("empty reader returns nil findings", func(t *testing.T) {
		t.Parallel()

		scanner := sensitive.NewScanner(sensitive.WithAll())
		r := strings.NewReader("")

		findings, err := scanner.ScanReader(r)
		if err != nil {
			t.Fatalf("ScanReader returned error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("reader error is propagated", func(t *testing.T) {
		t.Parallel()

		scanner := sensitive.NewScanner(sensitive.WithAll())
		r := &errorReader{err: io.ErrUnexpectedEOF}

		_, err := scanner.ScanReader(r)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("expected ErrUnexpectedEOF, got %v", err)
		}
	})
}

func TestScanner_ScanLines(t *testing.T) {
	t.Parallel()

	t.Run("calls fn for lines with findings", func(t *testing.T) {
		t.Parallel()

		scanner := sensitive.NewScanner(sensitive.WithEmail(), sensitive.WithPAN())
		input := "no sensitive data here\n" +
			"user tanaka@example.com logged in\n" +
			"another clean line\n" +
			"card 4532015112830366 charged\n"
		r := strings.NewReader(input)

		var results []struct {
			lineNum  int
			findings []sensitive.Finding
		}
		err := scanner.ScanLines(r, func(lineNum int, _ []byte, findings []sensitive.Finding) {
			results = append(results, struct {
				lineNum  int
				findings []sensitive.Finding
			}{lineNum, findings})
		})
		if err != nil {
			t.Fatalf("ScanLines returned error: %v", err)
		}

		if len(results) != 2 {
			t.Fatalf("expected fn called 2 times, got %d", len(results))
		}

		// Line 2: email
		if results[0].lineNum != 2 {
			t.Errorf("first result lineNum = %d, want 2", results[0].lineNum)
		}
		if results[0].findings[0].DetectorName != detector.NameEmail {
			t.Errorf("first result detector = %q, want email", results[0].findings[0].DetectorName)
		}

		// Line 4: PAN
		if results[1].lineNum != 4 {
			t.Errorf("second result lineNum = %d, want 4", results[1].lineNum)
		}
		if results[1].findings[0].DetectorName != detector.NamePAN {
			t.Errorf("second result detector = %q, want pan", results[1].findings[0].DetectorName)
		}
	})

	t.Run("empty reader calls fn zero times", func(t *testing.T) {
		t.Parallel()

		scanner := sensitive.NewScanner(sensitive.WithAll())
		r := strings.NewReader("")

		called := false
		err := scanner.ScanLines(r, func(_ int, _ []byte, _ []sensitive.Finding) {
			called = true
		})
		if err != nil {
			t.Fatalf("ScanLines returned error: %v", err)
		}
		if called {
			t.Error("fn should not be called for empty input")
		}
	})

	t.Run("reader error is propagated", func(t *testing.T) {
		t.Parallel()

		scanner := sensitive.NewScanner(sensitive.WithAll())
		// Create a reader that returns some data then errors.
		data := []byte("line one\nline two\n")
		r := io.MultiReader(bytes.NewReader(data), &errorReader{err: io.ErrUnexpectedEOF})

		err := scanner.ScanLines(r, func(_ int, _ []byte, _ []sensitive.Finding) {})
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("expected ErrUnexpectedEOF, got %v", err)
		}
	})
}

func TestScanner_ScanLines_lineBytesAreSafeToRetain(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithEmail())
	input := "user tanaka@example.com logged in\n" +
		"admin admin@example.com logged in\n"
	r := strings.NewReader(input)

	// Collect the line slices returned by the callback.
	var savedLines [][]byte
	err := scanner.ScanLines(r, func(_ int, line []byte, _ []sensitive.Finding) {
		savedLines = append(savedLines, line)
	})
	if err != nil {
		t.Fatalf("ScanLines returned error: %v", err)
	}
	if len(savedLines) != 2 {
		t.Fatalf("expected 2 callbacks, got %d", len(savedLines))
	}

	// After ScanLines returns, the retained line slices must still contain
	// the original content. Without the internal copy, bufio.Scanner would
	// have overwritten the buffer.
	if !bytes.Contains(savedLines[0], []byte("tanaka@example.com")) {
		t.Errorf("first retained line was corrupted: %q", savedLines[0])
	}
	if !bytes.Contains(savedLines[1], []byte("admin@example.com")) {
		t.Errorf("second retained line was corrupted: %q", savedLines[1])
	}
}

func TestScanner_ScanLines_longLineReturnsErrTooLong(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithEmail())

	// Build a single line that exceeds the 1 MB buffer limit.
	// The line contains an email so ScanLines would call fn if it could
	// read the line, but the line is too long for the internal buffer.
	longLine := make([]byte, 1024*1024+1)
	for i := range longLine {
		longLine[i] = 'x'
	}
	// No trailing newline — the entire input is a single oversized line.
	r := bytes.NewReader(longLine)

	err := scanner.ScanLines(r, func(_ int, _ []byte, _ []sensitive.Finding) {
		t.Error("fn should not be called for an oversized line")
	})
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("expected bufio.ErrTooLong, got %v", err)
	}
}

// errorReader is a test helper that always returns the configured error.
type errorReader struct {
	err error
}

func (r *errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
