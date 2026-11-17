package detect

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestURLPasswordFastPathDifferential(t *testing.T) {
	t.Parallel()
	fragments := []string{"worker completed request reference=example", "postgres://reader:fake@db.example/orders", "reader:fake@tcp(db.example:3306)/orders", "secret://token:fake@host/path", "redis://user:p%40ss@host", "a@b", "://", "@tcp(", "@unix(", "host:123", "token=value"}
	for b := range 256 {
		for _, left := range fragments {
			for _, right := range fragments {
				data := []byte(left + string(rune(b)) + right)
				got, want := urlPasswords(data), referenceURLPasswords(data)
				if !slices.EqualFunc(got, want, func(a, b Finding) bool {
					return a.Start == b.Start && a.End == b.End && a.Confidence == b.Confidence
				}) {
					t.Fatalf("differential mismatch at separator %d", b)
				}
			}
		}
	}
}

func TestDetectorCredentialProtocolBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ text, secret string }{
		{"postgres://token:short-secret@db.example/app", "short-secret"},
		{"postgres://alice:part;two@db.example/db", "part;two"},
		{"Authorization: Bearer  short-secret", "short-secret"},
		{"Authorization: Basic   ZmFrZTpmaWN0aXRpb3Vz", "ZmFrZTpmaWN0aXRpb3Vz"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			scanner := &Credential{}
			got := maskCredentialFindings(tc.text, scanner.Scan([]byte(tc.text)))
			if want := strings.Replace(tc.text, tc.secret, strings.Repeat("*", len(tc.secret)), 1); got != want {
				t.Errorf("got %q want %q", got, want)
			}
		})
	}
}

func TestFormattedURLExactPasswordSpans(t *testing.T) {
	t.Parallel()
	for _, user := range []string{"", "x", "alice"} {
		for _, secret := range []string{"x", "opaqueURLFixture", "opaque%40URLFixture", "part:tail"} {
			for _, before := range []string{" User:", "{Scheme:https Opaque: User:"} {
				before += user + ":"
				input := before + secret + " Host:example.invalid Path:/public}"
				got := (&Credential{}).Scan([]byte(input))
				if len(got) != 1 || got[0].Start != len(before) || got[0].End != len(before)+len(secret) || input[got[0].Start:got[0].End] != secret {
					t.Fatalf("formatted URL boundary: %q: %+v", input, got)
				}
			}
		}
	}
}

func TestCredentialURLDelimiters(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		want := strings.ContainsRune(" \t\r\n\"'<>", rune(b))
		if urlDelimiter(b) != want {
			t.Fatal(n)
		}
	}
}

func referenceURLPasswords(data []byte) []Finding {
	var out []Finding
	for start := 0; start < len(data); {
		if referenceURLDelimiter(data[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(data) && !referenceURLDelimiter(data[end]) {
			end++
		}
		segment := data[start:end]
		if scheme := bytes.Index(segment, []byte("://")); scheme >= 0 {
			start += scheme + len("://")
			segment = data[start:end]
			if tail := bytes.IndexAny(segment, "/?#"); tail >= 0 {
				segment = segment[:tail]
			}
		} else if !bytes.Contains(segment, []byte("@tcp(")) && !bytes.Contains(segment, []byte("@unix(")) {
			start = end
			continue
		}
		at := bytes.LastIndexByte(segment, '@')
		if at >= 0 {
			colon := bytes.IndexByte(segment[:at], ':')
			if colon >= 0 && !bytes.ContainsAny(segment[:colon], "/?#@") {
				secret := start + colon + 1
				stop := start + at
				if secret < stop && string(data[secret:stop]) != "[REDACTED]" {
					out = append(out, credentialFinding(secret, stop))
				}
			}
		}
		start = end
	}
	return out
}

func referenceURLDelimiter(b byte) bool { return strings.ContainsRune(" \t\r\n\"'<>", rune(b)) }
