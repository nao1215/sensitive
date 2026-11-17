package detect

import (
	"strings"
	"testing"
)

const (
	lowerHexAlphabet = "0123456789abcdef"
	alnumAlphabet    = "aZ3kQ9mX2bW7pL5nR8cV4tY6dH1fJ0gK"
	upperAlphabet    = "Q7Z3K9X2W5P8L4R6M1N0TBVCDFGHJ"
	letterAlphabet   = "qWeRtYuIoPaSdFgHjKlZxCvBnM"
	base64Alphabet   = "aZ3k+Q9m/X2bW7pL5nR8cV4tY6dH1fJ0gK"
)

// synthetic returns n bytes cycling through alphabet with a stride, so the
// value is varied like an issued credential but obviously fabricated.
func synthetic(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[(i*7+3)%len(alphabet)]
	}
	return string(b)
}

func uuidSample() string {
	return synthetic(lowerHexAlphabet, 8) + "-" + synthetic(lowerHexAlphabet, 4) + "-" + synthetic(lowerHexAlphabet, 4) + "-" + synthetic(lowerHexAlphabet, 4) + "-" + synthetic(lowerHexAlphabet, 12)
}

func providerSamples() map[string]string {
	hex := func(n int) string { return synthetic(lowerHexAlphabet, n) }
	alnum := func(n int) string { return synthetic(alnumAlphabet, n) }
	upper := func(n int) string { return synthetic(upperAlphabet, n) }
	return map[string]string{
		"1Password service account":  "ops_eyJ" + synthetic(base64Alphabet, 260) + "==",
		"1Password secret key":       "A3-" + upper(6) + "-" + upper(11) + "-" + upper(5) + "-" + upper(5) + "-" + upper(5),
		"1Password secret key v2":    "A3-" + upper(6) + "-" + upper(6) + "-" + upper(5) + "-" + upper(5) + "-" + upper(5) + "-" + upper(5),
		"Adobe client secret":        "p8e-" + alnum(32),
		"age secret key":             "AGE-SECRET-KEY-1" + synthetic("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", 58),
		"Airtable PAT":               "pat" + alnum(14) + "." + hex(64),
		"Alibaba access key":         "LTAI" + alnum(20),
		"Cloudflare origin CA":       "v1.0-" + hex(24) + "-" + hex(146),
		"Databricks":                 "dapi" + hex(32),
		"Databricks suffixed":        "dapi" + hex(32) + "-2",
		"DigitalOcean PAT":           "dop_v1_" + hex(64),
		"DigitalOcean OAuth":         "doo_v1_" + hex(64),
		"DigitalOcean refresh":       "dor_v1_" + hex(64),
		"Doppler":                    "dp.pt." + alnum(43),
		"Duffel":                     "duffel_test_" + alnum(43),
		"Dynatrace":                  "dt0c01." + alnum(24) + "." + alnum(64),
		"Flutterwave secret":         "FLWSECK_TEST-" + hex(32) + "-X",
		"Flutterwave encryption":     "FLWSECK_TEST-" + hex(12),
		"Frame.io":                   "fio-u-" + alnum(64),
		"GitLab CI job":              "glcbt-" + alnum(20),
		"GitLab deploy":              "gldt-" + alnum(20),
		"GitLab routable runner":     "glrt-t1_" + alnum(27) + ".01" + alnum(7),
		"GitLab trigger":             "glptt-" + hex(40),
		"GitLab runner registration": "GR1348941" + alnum(20),
		"Harness":                    "pat." + alnum(22) + "." + alnum(24) + "." + alnum(20),
		"42 intra":                   "s-s4t2ud-" + hex(64),
		"New Relic user":             "NRAK-" + upper(27),
		"New Relic browser":          "NRJS-" + hex(19),
		"Octopus Deploy":             "API-" + upper(26),
		"Postman":                    "PMAK-" + hex(24) + "-" + hex(34),
		"Prefect":                    "pnu_" + alnum(36),
		"Pulumi":                     "pul-" + hex(40),
		"RubyGems":                   "rubygems_" + hex(48),
		"Brevo":                      "xkeysib-" + hex(64) + "-" + alnum(16),
		"Sentry user":                "sntryu_" + hex(64),
		"SettleMint":                 "sm_pat_" + alnum(16),
		"Shippo":                     "shippo_live_" + hex(40),
		"Shopify":                    "shpat_" + hex(32),
		"Vault service":              "hvs." + alnum(95),
		"Twilio API key":             "SK" + hex(32),
		"Bedrock long-lived":         "ABSK" + synthetic(base64Alphabet, 120),
		"Fly.io":                     "fo1_" + alnum(43),
		"Grafana service account":    "glsa_" + alnum(32) + "_" + hex(8),
		"Grafana cloud":              "glc_" + synthetic(base64Alphabet, 40) + "=",
		"Grafana API key":            "eyJrIjoi" + alnum(80),
		"Hugging Face":               "hf_" + synthetic(letterAlphabet, 34),
		"PlanetScale":                "pscale_tkn_" + alnum(40),
		"Sourcegraph":                "sgp_" + hex(16) + "_" + hex(40),
		"Facebook page":              "EAAM" + alnum(120),
		"Clojars":                    "CLOJARS_" + alnum(60),
		"EasyPost":                   "EZAK" + alnum(54),
		"Heroku v2":                  "HRKU-AA" + alnum(58),
		"Perplexity":                 "pplx-" + alnum(48),
		"Notion":                     "ntn_" + alnum(46),
		"Linear":                     "lin_api_" + alnum(40),
		"Artifactory":                "AKCp" + alnum(69),
		"OpenShift":                  "sha256~" + alnum(43),
		"Plaid":                      "access-sandbox-" + uuidSample(),
		"SendGrid extended":          "SG." + alnum(30) + "." + alnum(35),
		"Slack app":                  "xapp-1-A" + upper(10) + "-" + "1234567890123" + "-" + hex(64),
		"OpenAI admin":               "sk-admin-" + alnum(40),
		"OpenAI legacy":              "sk-" + alnum(48),
		"SonarQube":                  "squ_" + alnum(40),
		"Yandex API":                 "AQVN" + alnum(36),
		"Mailgun":                    "key-" + hex(32),
	}
}

func TestProviderRuleLayouts(t *testing.T) {
	t.Parallel()
	d := NewServiceToken()
	for name, value := range providerSamples() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			text := "auth failed: " + value + " retry"
			got := d.Scan([]byte(text))
			start := len("auth failed: ")
			if len(got) != 1 || got[0].Start != start || got[0].End != start+len(value) {
				t.Fatalf("Scan(%q) = %+v, want one span [%d,%d)", text, got, start, start+len(value))
			}
		})
	}
}

func TestProviderRuleRejectsNearMisses(t *testing.T) {
	t.Parallel()
	d := NewServiceToken()
	hex := func(n int) string { return synthetic(lowerHexAlphabet, n) }
	for name, text := range map[string]string{
		"short fixed body":       "dop_v1_" + hex(63),
		"long fixed body":        "dop_v1_" + hex(65),
		"wrong alphabet":         "shpat_" + strings.Repeat("g", 32),
		"placeholder":            "glsoat-" + strings.Repeat("x", 24),
		"placeholder digits":     "pnu_" + strings.Repeat("0", 36),
		"inside identifier":      "mypul-" + hex(40),
		"missing second segment": "PMAK-" + hex(24),
		"lower-case prefix":      "sk" + hex(32),
		"ordinary API word":      "API-GATEWAY-TIMEOUT",
		"ordinary path":          "path=/var/lib/patterns",
		"Twilio with tail":       "SK" + hex(32) + "z",
		"hash after key":         "key-" + hex(40),
	} {
		if got := d.Scan([]byte(text)); len(got) != 0 {
			t.Errorf("%s: Scan(%q) = %+v, want none", name, text, got)
		}
	}
}

func TestPlaceholderBody(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		body string
		want bool
	}{
		{"xxxxxxxx", true},
		{"xxxx-xxxx_xxxx.xxxx", true},
		{"", true},
		{"xxxxxxxy", false},
		{"0000-0001", false},
	} {
		if got := placeholderBody([]byte(tc.body)); got != tc.want {
			t.Errorf("placeholderBody(%q) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

func TestRoutingSuffixEnd(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want int
	}{
		{".01abc", 6},
		{".01.abc def", 7},
		{". next", 0},
		{"..x", 0},
		{"", 0},
	} {
		if got := routingSuffixEnd([]byte(tc.text), 0); got != tc.want {
			t.Errorf("routingSuffixEnd(%q) = %d, want %d", tc.text, got, tc.want)
		}
	}
}

func TestProviderIndexKeepsZeroValueUsable(t *testing.T) {
	t.Parallel()
	value := "pul-" + synthetic(lowerHexAlphabet, 40)
	if got := (&ServiceToken{}).Scan([]byte(value)); len(got) != 1 {
		t.Fatalf("zero-value ServiceToken missed %q: %+v", value, got)
	}
}

func TestServiceTokenHintsCoverEveryRule(t *testing.T) {
	t.Parallel()
	hints := (&ServiceToken{}).Hints()
	for name, value := range providerSamples() {
		found := false
		for _, hint := range hints {
			if strings.Contains(strings.ToLower(value), strings.ToLower(string(hint))) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: no hint occurs in %q", name, value)
		}
	}
}

func TestProviderLayoutsParse(t *testing.T) {
	t.Parallel()
	for _, layout := range providerLayouts() {
		if _, err := parseLayout(layout); err != nil {
			t.Error(err)
		}
	}
}

func TestParseLayoutNotation(t *testing.T) {
	t.Parallel()
	rule, err := parseLayout(providerLayout{prefix: "x_", layout: "h4 -a2-3 _t1+ =2 ~"})
	if err != nil {
		t.Fatal(err)
	}
	if !rule.dotted || rule.pad != 2 || len(rule.segments) != 3 {
		t.Fatalf("parseLayout = %+v", rule)
	}
	for i, want := range []tokenSegment{{min: 4, max: 4}, {min: 2, max: 3, sep: '-'}, {min: 1, max: 0, sep: '_'}} {
		got := rule.segments[i]
		if got.min != want.min || got.max != want.max || got.sep != want.sep || got.class == nil {
			t.Errorf("segment %d = %+v, want %+v", i, got, want)
		}
	}
	for _, layout := range []providerLayout{
		{prefix: "", layout: "h4"},
		{prefix: "x", layout: ""},
		{prefix: "x", layout: "q4"},
		{prefix: "x", layout: "-"},
		{prefix: "x", layout: "h0"},
		{prefix: "x", layout: "h4-2"},
		{prefix: "x", layout: "h2-4+"},
		{prefix: "x", layout: "hx"},
		{prefix: "x", layout: "h4 =x"},
		{prefix: "x", layout: "h4 =0"},
	} {
		if _, err := parseLayout(layout); err == nil {
			t.Errorf("parseLayout(%+v) accepted invalid notation", layout)
		}
	}
}
