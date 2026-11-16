package detect

import (
	"strings"
	"testing"
)

func TestServiceTokenFormats(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"sk-proj-", "sk-svcacct-", "sk-ant-api03-", "sk_live_", "rk_live_", "whsec_", "glpat-", "npm_", "pypi-", "GOCSPX-"} {
		t.Run(prefix, func(t *testing.T) {
			t.Parallel()
			value := prefix + strings.Repeat("Fake0", 8)
			text := "failed " + value + " done"
			got := (&ServiceToken{}).Scan([]byte(text))
			if len(got) != 1 || got[0].Start != 7 || got[0].End != 7+len(value) {
				t.Fatalf("unexpected spans: %v", got)
			}
		})
	}
	for _, value := range []string{"SG." + strings.Repeat("f", 22) + "." + strings.Repeat("x", 43), "https://hooks.slack.com/services/TFAKE/BFAKE/" + strings.Repeat("x", 24)} {
		if len((&ServiceToken{}).Scan([]byte(value))) != 1 {
			t.Error("format was missed")
		}
	}
	for _, value := range []string{"sk-proj-help", "npm_package_name", "pypi-package-docs", "GOCSPX-short", "pk_live_" + strings.Repeat("x", 24), "commit " + strings.Repeat("abcdef01", 5)} {
		if len((&ServiceToken{}).Scan([]byte(value))) != 0 {
			t.Error("ordinary identifier was detected")
		}
	}
}

func TestEntropyCandidates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg", true},
		{strings.Repeat("a", 48), false},
		{"550e8400-e29b-41d4-a716-446655440000", false},
		{"https://example.com/" + strings.Repeat("abcdef0123", 4), false},
		{"request_id=q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg", false},
	} {
		if got := len((&HighEntropy{}).Scan([]byte(tc.text))) > 0; got != tc.want {
			t.Errorf("candidate mismatch: %v", got)
		}
	}
}

func TestSendGridInvalidBody(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		"SG." + strings.Repeat("a", 21) + "!." + strings.Repeat("b", 43),
		"SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 42) + "!",
	} {
		if got := (&ServiceToken{}).Scan([]byte(text)); len(got) != 0 {
			t.Fatal("punctuation accepted as a SendGrid credential byte")
		}
	}
}
