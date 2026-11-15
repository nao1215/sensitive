package embargo_test

import (
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func FuzzMask(f *testing.F) {
	f.Add("abcdef", 1, 4, 3, 5)
	f.Add("日本語", 0, 3, 3, 6)
	f.Fuzz(func(t *testing.T, text string, a, b, c, d int) {
		spans := []embargo.Finding{{Kind: "a", Start: a, End: b, Confidence: 1}, {Kind: "b", Start: c, End: d, Confidence: 1}}
		calls := 0
		got := embargo.MaskFunc(text, spans, func(_ embargo.Kind, v string) string { calls++; return strings.Repeat("*", len(v)) })
		invalid := a < 0 || b <= a || b > len(text) || c < 0 || d <= c || d > len(text)
		if invalid {
			//nolint:goconst // Assert the literal public redaction contract.
			if got != "[REDACTED]" || calls != 0 {
				t.Fatal("invalid spans passed")
			}
			return
		}
		want := []byte(text)
		for i := range want {
			if (i >= a && i < b) || (i >= c && i < d) {
				want[i] = '*'
			}
		}
		if got != string(want) {
			t.Fatal("union missed a byte")
		}
	})
}
