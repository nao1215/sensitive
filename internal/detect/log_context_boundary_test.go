package detect

import (
	"strings"
	"testing"
)

func TestEntropyPunctuationAndModuleBoundaries(t *testing.T) {
	t.Parallel()
	// #nosec G101 -- Synthetic mixed-alphabet input for the entropy boundary test.
	const token = "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg"
	for _, tc := range []struct {
		text string
		want int
	}{
		{"." + token, 1},
		{token + ".", 1},
		{"[." + token + ".]", 1},
		{"a." + token, 0},
		{token + ".a", 0},
	} {
		if got := (&HighEntropy{}).Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("punctuation versus module component %q: %v", tc.text, got)
		}
	}
}

func TestSWIFTSlashListAndSourcePath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want int
	}{
		{"swift=DEUTDEFF/COBADEFF", 2},
		{"BIC: DEUTDEFF/COBADEFF/CHASUS33", 3},
		{"swift source=/tmp/COBADEFF", 0},
		{"swift source=DEUTDEFF.log", 0},
		{"swift source=/DEUTDEFF", 0},
		{"swift source=DEUTDEFF/tmp", 0},
		{"swift source=DEUTDEFF/NOTACODE99", 0},
		{"swift source=DEUTDEFF/COBADEFF01", 0},
		{"swift source=NOTACODE99/DEUTDEFF", 0},
	} {
		if got := NewSWIFTBIC().Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("SWIFT list versus source path %q: %v", tc.text, got)
		}
	}
}

func BenchmarkABALeadingWhitespace(b *testing.B) {
	input := []byte(strings.Repeat(" ", 1<<20) + strings.Repeat("021000021 ", 10000))
	detector := NewABARouting()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		if len(detector.Scan(input)) != 10000 {
			b.Fatal("standalone ABA values were lost after leading whitespace")
		}
	}
}

func TestNumberHostnameAndSentenceBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want int
	}{
		{"1.111111111118", 0},
		{"No.111111111118", 1},
		{"_-111111111118", 0},
		{"111111111118.example.test", 0},
		{"111111111118-a.example.test", 0},
		{"111111111118.", 1},
		{"111111111118. end", 1},
		{"111111111118-host!.text", 1},
		{"111111111118-note", 1},
	} {
		if got := NewMyNumber().Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("numeric context %q: %v", tc.text, got)
		}
	}
}

func TestJavaIdentityTokenBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want int
	}{
		{"token=A@a", 0},
		{"token=Z@1234567890abcdef", 0},
		{"token=A@1234567890abcdef0", 1},
		{`token="A@a"`, 1},
		{`token='Z@a'`, 1},
		{"token=a@a", 1},
		{"token=@a", 1},
	} {
		if got := (&Credential{}).Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("Java identity versus opaque string %q: %v", tc.text, got)
		}
	}
}
