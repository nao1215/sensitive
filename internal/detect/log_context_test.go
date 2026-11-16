package detect

import (
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

func TestLogContextPreservesStandaloneValues(t *testing.T) {
	t.Parallel()
	for _, text := range []string{`token=Example@zz`, `token="Example@a"`, `token=Example@12345678901234567`, `token=example@a`, `token=Foo!@a`, `token=@a`, `token=Example@`} {
		if len((&Credential{}).Scan([]byte(text))) != 1 {
			t.Errorf("string token lost: %s", text)
		}
	}
	for _, text := range []string{"111111111118", "111111111118-note", "111111111118-", "111111111118;"} {
		if len(NewMyNumber().Scan([]byte(text))) != 1 {
			t.Errorf("standalone number lost: %s", text)
		}
	}
}
