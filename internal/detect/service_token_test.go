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

func TestServiceTokenSpecialLayouts(t *testing.T) {
	t.Parallel()
	hex := func(n int) string { return synthetic(lowerHexAlphabet, n) }
	alnum := func(n int) string { return synthetic(alnumAlphabet, n) }
	teamsPath := uuidSample() + "@" + uuidSample() + "/IncomingWebhook/" + alnum(32) + "/" + uuidSample()
	for _, tc := range []struct {
		name, text, secret string
	}{
		{"Terraform Cloud", "token " + alnum(14) + ".atlasv1." + alnum(64) + " end", alnum(14) + ".atlasv1." + alnum(64)},
		{"Entra client secret", "secret " + "abc8Q~" + alnum(34) + " end", "abc8Q~" + alnum(34)},
		{"Entra secret before a full stop", "secret " + "abc8Q~" + alnum(33) + ". end", "abc8Q~" + alnum(33)},
		{"Telegram bot", "bot 123456789:A" + alnum(34) + " end", "123456789:A" + alnum(34)},
		{"Telegram Bot API URL", "GET https://api.telegram.org/bot123456789:A" + alnum(34) + "/sendMessage", "123456789:A" + alnum(34)},
		{"MaxMind", "license " + alnum(6) + "_" + alnum(29) + "_mmk end", alnum(6) + "_" + alnum(29) + "_mmk"},
		{"Mailchimp", "key " + hex(32) + "-us18 end", hex(32) + "-us18"},
		{"Facebook app token", "token 123456789012345|" + alnum(30) + " end", "123456789012345|" + alnum(30)},
		{"Slack workflow", "url https://hooks.slack.com/workflows/TFAKE/AFAKE/123456/" + alnum(24) + " end", "TFAKE/AFAKE/123456/" + alnum(24)},
		{"Slack trigger without scheme", "url hooks.slack.com/triggers/TFAKE/123456/" + alnum(24) + " end", "TFAKE/123456/" + alnum(24)},
		{"Slack http", "url http://hooks.slack.com/services/TFAKE/BFAKE/" + alnum(24) + " end", "TFAKE/BFAKE/" + alnum(24)},
		{"Teams webhook", "url https://contoso.webhook.office.com/webhookb2/" + teamsPath + " end", teamsPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := NewServiceToken().Scan([]byte(tc.text))
			start := strings.Index(tc.text, tc.secret)
			if len(got) != 1 || got[0].Start != start || got[0].End != start+len(tc.secret) {
				t.Fatalf("Scan(%q) = %+v, want [%d,%d)", tc.text, got, start, start+len(tc.secret))
			}
		})
	}
}

func TestServiceTokenSpecialLayoutNearMisses(t *testing.T) {
	t.Parallel()
	alnum := func(n int) string { return synthetic(alnumAlphabet, n) }
	// #nosec G101 -- These synthetic near misses are negative detection fixtures, not credentials.
	for name, text := range map[string]string{
		"Terraform short body":      alnum(14) + ".atlasv1." + alnum(20),
		"Entra without digit":       "abcdQ~" + alnum(34),
		"Entra short tail":          "abc8Q~" + alnum(10),
		"time with colon":           "uptime 12345:Abc",
		"Telegram long secret":      "123456789:A" + alnum(40),
		"Telegram inside word":      "xbot123456789:A" + alnum(34),
		"MaxMind wrong suffix":      alnum(6) + "_" + alnum(29) + "_mmx",
		"Mailchimp upper hex":       strings.ToUpper(synthetic(lowerHexAlphabet, 32)) + "-us18",
		"pipe table":                "| 123456789012345 | total |",
		"Slack services four parts": "https://hooks.slack.com/services/TFAKE/BFAKE/CFAKE/" + alnum(24),
		"Slack one-byte part":       "https://hooks.slack.com/services/T/BFAKE/" + alnum(24),
		"Teams without secret path": "https://contoso.webhook.office.com/webhookb2/short",
	} {
		if got := NewServiceToken().Scan([]byte(text)); len(got) != 0 {
			t.Errorf("%s: Scan(%q) = %+v, want none", name, text, got)
		}
	}
}
