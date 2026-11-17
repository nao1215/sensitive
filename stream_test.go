package embargo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

func TestScanner_ScanLines(t *testing.T) {
	t.Parallel()

	t.Run("calls fn for lines with findings", func(t *testing.T) {
		t.Parallel()

		scanner := NewScanner(WithKinds(KindEmail, KindPAN))
		input := "no sensitive data here\n" +
			"user tanaka@example.com logged in\n" +
			"another clean line\n" +
			"card 4532015112830366 charged\n"
		r := strings.NewReader(input)

		var results []struct {
			findings []Finding
			lineNum  int
		}
		err := scanner.ScanLines(r, func(lineNum int, _ []byte, findings []Finding) {
			results = append(results, struct {
				findings []Finding
				lineNum  int
			}{lineNum: lineNum, findings: findings})
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
		if results[0].findings[0].Kind != KindEmail {
			t.Errorf("first result detector = %q, want email", results[0].findings[0].Kind)
		}

		// Line 4: PAN
		if results[1].lineNum != 4 {
			t.Errorf("second result lineNum = %d, want 4", results[1].lineNum)
		}
		if results[1].findings[0].Kind != KindPAN {
			t.Errorf("second result detector = %q, want pan", results[1].findings[0].Kind)
		}
	})

	t.Run("empty reader calls fn zero times", func(t *testing.T) {
		t.Parallel()

		scanner := NewScanner(WithAll())
		r := strings.NewReader("")

		called := false
		err := scanner.ScanLines(r, func(_ int, _ []byte, _ []Finding) {
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

		scanner := NewScanner(WithAll())
		// Create a reader that returns some data then errors.
		data := []byte("line one\nline two\n")
		r := io.MultiReader(bytes.NewReader(data), &errorReader{err: io.ErrUnexpectedEOF})

		err := scanner.ScanLines(r, func(_ int, _ []byte, _ []Finding) {})
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("expected ErrUnexpectedEOF, got %v", err)
		}
	})
}

func TestScanner_ScanLines_lineBytesAreSafeToRetain(t *testing.T) {
	t.Parallel()

	scanner := NewScanner(WithKinds(KindEmail))
	input := "user tanaka@example.com logged in\n" +
		"admin admin@example.com logged in\n"
	r := strings.NewReader(input)

	// Collect the line slices returned by the callback.
	var savedLines [][]byte
	err := scanner.ScanLines(r, func(_ int, line []byte, _ []Finding) {
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

	scanner := NewScanner(WithKinds(KindEmail))

	// Build a single line that exceeds the 1 MB buffer limit.
	// The line contains an email so ScanLines would call fn if it could
	// read the line, but the line is too long for the internal buffer.
	longLine := make([]byte, 1024*1024+1)
	for i := range longLine {
		longLine[i] = 'x'
	}
	// No trailing newline — the entire input is a single oversized line.
	r := bytes.NewReader(longLine)

	err := scanner.ScanLines(r, func(_ int, _ []byte, _ []Finding) {
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

func TestScannerPathsAtBufferBoundaries(t *testing.T) {
	t.Parallel()
	s := NewScanner(WithAll())
	// ScanLines reports line-relative offsets and cannot match across newlines;
	// this equivalence deliberately uses one line below the documented 1 MiB cap.
	for _, offset := range []int{0, 1, 509, 510, 511, 512, 4093, 4095, 4096, 65515, 65535, 65536, 131071} {
		input := strings.Repeat(".", offset) + " [tanaka@example.com] [GB82WEST12345698765432] end"
		want := keysOf(s.Scan([]byte(input)))
		if !sameKeys(want, keysOf(s.ScanString(input))) {
			t.Fatal("ScanString differs")
		}
		var lines []Finding
		err := s.ScanLines(strings.NewReader(input), func(_ int, _ []byte, findings []Finding) { lines = append(lines, findings...) })
		if err != nil || !sameKeys(want, keysOf(lines)) {
			t.Fatalf("lines offset %d: %v", offset, err)
		}
	}
}

//nolint:gocognit // Keep encoding, newline, nested frame and truncation axes visible in one differential property.
func TestPEMTruncationProperty(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindPrivateKeyPEM))
	for _, label := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "ANY PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
		header, footer := "-----BEGIN "+label+"-----", "-----END "+label+"-----"
		for _, newline := range []string{"\n", "\r\n"} {
			for _, nested := range []bool{false, true} {
				for encoding := -1; encoding <= len(header)+len(footer); encoding++ {
					head, tail := header, footer
					if encoding < len(header) && encoding >= 0 {
						head = percentFrameByte(header, encoding)
					}
					if encoding >= len(header) && encoding < len(header)+len(footer) {
						tail = percentFrameByte(footer, encoding-len(header))
					}
					if encoding == len(header)+len(footer) {
						head, tail = percentFrame(header), percentFrame(footer)
					}
					lines := []string{head, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", tail}
					if nested {
						lines = append(lines[:2], append([]string{"-----BEGIN PUBLIC KEY-----"}, lines[2:]...)...)
					}
					for cut := 1; cut <= len(lines); cut++ {
						input := strings.Join(lines[:cut], newline)
						if got := Mask(input, scanner.ScanString(input)); got != redactionMarker {
							t.Errorf("whole %s/%d/%d: %q", label, encoding, cut, got)
						}
						seen := 0
						if err := scanner.ScanLines(strings.NewReader(input), func(n int, line []byte, findings []Finding) {
							seen++
							if n != seen || Mask(string(line), findings) != redactionMarker {
								t.Errorf("line %d of %s/%d retained", n, label, encoding)
							}
						}); err != nil {
							t.Fatal(err)
						}
						if seen != cut {
							t.Errorf("only %d/%d lines for %s/%d", seen, cut, label, encoding)
						}
					}
					// Matching encoded footers must also end continuation state.
					if err := scanner.ScanLines(strings.NewReader(strings.Join(lines, newline)+newline+"visible"), func(_ int, line []byte, _ []Finding) {
						if string(line) == "visible" {
							t.Errorf("state survived footer %s/%d", label, encoding)
						}
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}

func percentFrameByte(s string, at int) string {
	return s[:at] + fmt.Sprintf("%%%02X", s[at]) + s[at+1:]
}

func percentFrame(s string) string {
	var b strings.Builder
	for i := range len(s) {
		if _, err := fmt.Fprintf(&b, "%%%02X", s[i]); err != nil {
			panic(err)
		}
	}
	return b.String()
}

func TestPEMStreamTransitions(t *testing.T) {
	t.Parallel()
	begin := "-----BEGIN " + "PRIVATE KEY-----"
	end := "-----END PRIVATE KEY-----"
	for _, body := range []string{begin + "\nfirst\n" + begin + "\nsecond\n" + end + " trailing\nvisible", begin + "\n\nfirst\n" + end + "\nvisible"} {
		scanner := NewScanner(WithKinds(KindPrivateKeyPEM))
		if err := scanner.ScanLines(strings.NewReader(body), func(_ int, line []byte, f []Finding) {
			got := Mask(string(line), f)
			if strings.Contains(got, "first") || strings.Contains(got, "second") || string(line) == "visible" {
				t.Fatalf("wrong PEM state: %q", got)
			}
		}); err != nil {
			t.Fatal(err)
		}
		// State must not survive a ScanLines call, nor enable a disabled detector.
		for _, s := range []*Scanner{scanner, NewScanner(WithKinds()), NewScanner(WithMinConfidence(1))} {
			if err := s.ScanLines(strings.NewReader("first\nsecond"), func(int, []byte, []Finding) { t.Error("state crossed calls or policy") }); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestTruncatedPEMDoesNotTrustNestedHeaders(t *testing.T) {
	t.Parallel()
	input := "-----BEGIN " + "PRIVATE KEY-----\nYWJjZGVm\n-----BEGIN PUBLIC KEY-----\nQUJDREVG"
	scanner := NewScanner(WithKinds(KindPrivateKeyPEM))
	if got := Mask(input, scanner.ScanString(input)); got != redactionMarker {
		t.Errorf("incomplete private key retained text: %q", got)
	}
	lines := 0
	if err := scanner.ScanLines(strings.NewReader(input), func(_ int, line []byte, f []Finding) {
		lines++
		if Mask(string(line), f) != redactionMarker {
			t.Error("PEM continuation visible")
		}
	}); err != nil {
		t.Fatal(err)
	}
	if lines != 4 {
		t.Fatalf("only %d key lines reported", lines)
	}
}

func TestPEMLineStateRejectsUnrelatedCustomFinding(t *testing.T) {
	t.Parallel()
	// A custom finding with the PEM kind is not proof of a BEGIN header.
	raw := []byte("unrelated text")
	finding := Finding{Kind: KindPrivateKeyPEM, Start: 0, End: len(raw), Confidence: 1}
	if footer := pemLineLabel(detect.View{Raw: raw, Data: raw}, []Finding{finding}, 0); footer != nil {
		t.Fatal("custom finding entered PEM state")
	}
	view := detect.NewView([]byte("%2D----BEGIN PRIVATE KEY-----"))
	finding.Start = 1 // Inside the encoded byte, not a normalized boundary.
	if label := pemLineLabel(view, []Finding{finding}, 0); label != nil {
		t.Fatal("unaligned custom finding entered PEM state")
	}
}

func TestZeroScannerCarriesEncodedPEMState(t *testing.T) {
	t.Parallel()
	var scanner Scanner
	input := "%2D----BEGIN PRIVATE KEY-----\nfixtureBody\n-----END PRIVATE KEY-----"
	seen := 0
	if err := scanner.ScanLines(strings.NewReader(input), func(_ int, line []byte, findings []Finding) {
		seen++
		if Mask(string(line), findings) != redactionMarker {
			t.Fatal("zero scanner leaked block")
		}
	}); err != nil || seen != 3 {
		t.Fatalf("zero scanner callbacks=%d error=%v", seen, err)
	}
}
