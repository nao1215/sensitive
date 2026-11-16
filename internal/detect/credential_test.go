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
					return a.Start == b.Start && a.End == b.End && a.Confidence == b.Confidence && a.RawValue == b.RawValue
				}) {
					t.Fatalf("differential mismatch at separator %d", b)
				}
			}
		}
	}
}

//nolint:dupl // Keep the pre-optimization parser as an independent differential oracle.
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
					out = append(out, credentialFinding(data, secret, stop))
				}
			}
		}
		start = end
	}
	return out
}

func referenceURLDelimiter(b byte) bool { return strings.ContainsRune(" \t\r\n\"'<>", rune(b)) }

func TestCredentialBoundaryContract(t *testing.T) {
	t.Parallel()
	for _, d := range []Detector{NewAWSKey(), NewGitHubToken(), NewGoogleAPIKey(), NewSlackToken(), NewETH()} {
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		raw := map[DetectorName]string{NameAWSKey: sampleAccessKey, NameGitHubToken: "ghp_" + strings.Repeat("a", 36), NameGoogleAPIKey: "AIza" + strings.Repeat("a", 35), NameSlackToken: "xoxb-" + strings.Repeat("a", 10), NameETH: "0x" + strings.Repeat("a", 40)}[d.Name()]
		for _, b := range []byte("AZaz09_") {
			if d.Name() == NameAWSKey && b == '_' {
				continue
			}
			for _, text := range []string{string(b) + raw, raw + string(b)} {
				// Variable-length Slack tokens absorb a valid suffix by design.
				if d.Name() == NameSlackToken && strings.HasPrefix(text, raw) && b != '_' {
					continue
				}
				if got := d.Scan([]byte(text)); len(got) != 0 {
					t.Fatalf("%s boundary %q: %+v", d.Name(), text, got)
				}
			}
		}
	}
}

func TestAWSSecretPairBoundaries(t *testing.T) {
	t.Parallel()
	access := "AKIA" + strings.Repeat("A", 16)
	value := "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg01234567"
	for _, tc := range []struct {
		text string
		want int
	}{
		{access + " " + value, 1},
		{value + " " + access, 1},
		{access + " " + value[:39], 0},
		{access + " " + value + "Z", 0},
		{access + strings.Repeat(" ", 129) + value, 0},
	} {
		got := (&Credential{}).Scan([]byte(tc.text))
		if len(got) != tc.want {
			t.Fatalf("pair length/boundary mismatch: %v", got)
		}
		if tc.want == 1 && tc.text[got[0].Start:got[0].End] != value {
			t.Fatal("pair span changed")
		}
	}
}

func TestCredentialLongUnknownKey(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("field", 8) + "=opaque-value password=actual-test-password"
	got := (&Credential{}).Scan([]byte(text))
	if len(got) != 1 || text[got[0].Start:got[0].End] != "actual-test-password" {
		t.Fatal("unknown long key masked or following password lost")
	}
}
