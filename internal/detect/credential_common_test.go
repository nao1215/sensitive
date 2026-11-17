package detect

import (
	"bytes"
	"strings"
	"testing"
)

func TestCredentialAndNetworkAlphabetEdges(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		upper := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", rune(b))
		alnum := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", rune(b))
		if isUpperAlphaNum(b) != upper || isAlphaNum(b) != alnum {
			t.Fatalf("credential byte %x", b)
		}
		if isTokenByte(b) != (alnum || strings.ContainsRune("_-", rune(b))) {
			t.Fatalf("payment byte %x", b)
		}
		if isBase58Char(b) != strings.ContainsRune("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", rune(b)) {
			t.Fatalf("base58 byte %x", b)
		}
		if toUpperByte(b) != bytes.ToUpper([]byte{b})[0] && b < 128 {
			t.Fatalf("uppercase %x", b)
		}
	}
	for _, s := range []string{"aA", "fF", "aF", "fA", "09af", "09AF"} {
		want := hexCaseMixed
		if s == strings.ToLower(s) || s == strings.ToUpper(s) {
			want = hexCaseUniform
		}
		if hexCaseType(s) != want {
			t.Fatalf("hex case %q", s)
		}
	}
}

func TestCredentialMinimumLengths(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d      Detector
		prefix string
		min    int
	}{
		{NewGitHubToken(), "github_pat_", 22},
		{NewSlackToken(), "xoxb-", 10},
		{NewPaymentToken(), "sk_test_", 16},
		{NewPaymentToken(), "tok_", 8},
	} {
		for _, n := range []int{tc.min - 1, tc.min, tc.min + 1} {
			raw := tc.prefix + strings.Repeat("a", n)
			got := tc.d.Scan([]byte(raw + " " + raw))
			if n < tc.min {
				if len(got) != 0 {
					t.Fatal(tc.prefix, n, got)
				}
				continue
			}
			if len(got) != 2 || got[0].Start != 0 || got[0].End != len(raw) || got[1].Start != len(raw)+1 || got[1].End != 2*len(raw)+1 {
				t.Fatal(tc.prefix, n, got)
			}
		}
	}
}
