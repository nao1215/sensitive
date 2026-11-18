package detect

import (
	"strings"
	"testing"
)

func TestEmailDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "simple email",
			input:      "contact tanaka@example.com for info",
			wantLen:    1,
			wantRaw:    "tanaka@example.com",
			wantMinCon: 0.7,
		},
		{
			name:       "email with subdomain",
			input:      "mail to user@mail.example.co.jp",
			wantLen:    1,
			wantRaw:    "user@mail.example.co.jp",
			wantMinCon: 0.7,
		},
		{
			name:       "email with plus addressing",
			input:      "send to user+tag@example.com",
			wantLen:    1,
			wantRaw:    "user+tag@example.com",
			wantMinCon: 0.7,
		},
		{
			name:       "multiple emails",
			input:      "from alice@example.com to bob@example.org",
			wantLen:    2,
			wantRaw:    "",
			wantMinCon: 0.7,
		},
		{
			name:       "email in angle brackets",
			input:      "<admin@example.com>",
			wantLen:    1,
			wantRaw:    "admin@example.com",
			wantMinCon: 0.7,
		},

		// False positives that should NOT be detected
		{
			name:    "@ alone",
			input:   "@ sign",
			wantLen: 0,
		},
		{
			name:    "no domain",
			input:   "user@",
			wantLen: 0,
		},
		{
			name:    "no local part",
			input:   "@example.com",
			wantLen: 0,
		},
		{
			name:    "no TLD",
			input:   "user@localhost",
			wantLen: 0,
		},
		{
			name:    emptyInputCase,
			input:   "",
			wantLen: 0,
		},
		{
			name:    "single char TLD",
			input:   "user@example.c",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assertDetectorScan(t, d, tt.input, tt.wantLen, tt.wantRaw, tt.wantMinCon)
		})
	}
}

func TestEmailDetector_UppercaseTLD(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	findings := d.Scan([]byte("user@EXAMPLE.COM"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	// Known TLD "COM" should be recognized case-insensitively, giving >= 0.9.
	if findings[0].Confidence < 0.9 {
		t.Errorf("Confidence = %f, want >= 0.9 for uppercase known TLD", findings[0].Confidence)
	}
}

func TestEmailDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	findings := d.Scan([]byte("tanaka@example.com"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	matched := "tanaka@example.com"[findings[0].Start:findings[0].End]
	if strings.Split(matched, "@")[0] != "tanaka" {
		t.Errorf("Local = %q, want %q", strings.Split(matched, "@")[0], "tanaka")
	}
	if strings.Split(matched, "@")[1] != "example.com" {
		t.Errorf("Domain = %q, want %q", strings.Split(matched, "@")[1], "example.com")
	}
}

func TestEmailDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	if d.Name() != NameEmail {
		t.Errorf("Name() = %q, want %q", d.Name(), NameEmail)
	}
}

func TestEmailDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	hints := d.Hints()
	if len(hints) != 2 || string(hints[0]) != "@" || string(hints[1]) != "＠" {
		t.Errorf("Hints() = %q, want @ and full-width ＠", hints)
	}
}

func TestEmailDetector_ConsecutiveDots(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	findings := d.Scan([]byte("user@example..com"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Confidence > 0.9 {
		t.Errorf("Confidence = %f, want <= 0.9 for consecutive dots", findings[0].Confidence)
	}
}

func TestEmailDetector_DotAtLocalEnd(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	findings := d.Scan([]byte("user.@example.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for dot at end of local part, want 0", len(findings))
	}
}

func TestEmailDetector_DotAtLocalStart(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	findings := d.Scan([]byte(".user@example.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for dot at start of local part, want 0", len(findings))
	}
}

func TestEmailDetector_UnknownTLD(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	findings := d.Scan([]byte("user@example.xyz"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Confidence >= 0.9 {
		t.Errorf("Confidence = %f, want < 0.9 for unknown TLD", findings[0].Confidence)
	}
}

func TestEmailDetector_TrailingDotDomain(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	findings := d.Scan([]byte("user@example.com."))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if "user@example.com."[findings[0].Start:findings[0].End] != "user@example.com" {
		t.Errorf("matched text = %q, want %q", "user@example.com."[findings[0].Start:findings[0].End], "user@example.com")
	}
}

func TestEmailDetector_TrailingDashDomain(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	findings := d.Scan([]byte("user@example.com-"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if "user@example.com-"[findings[0].Start:findings[0].End] != "user@example.com" {
		t.Errorf("matched text = %q, want %q", "user@example.com-"[findings[0].Start:findings[0].End], "user@example.com")
	}
}

func TestEmailDetector_NumericTLD(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	// TLD with digits should not be detected.
	findings := d.Scan([]byte("user@example.c0m"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for numeric TLD, want 0", len(findings))
	}
}

func TestEmailDetector_ConsecutiveDotsLocal(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	// Consecutive dots in local part are forbidden by RFC 5321.
	findings := d.Scan([]byte("user..name@example.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for consecutive dots in local part, want 0", len(findings))
	}
}

func TestEmailDetector_DomainLabelStartsWithDash(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	// Domain label starting with '-' is invalid per RFC 5321.
	findings := d.Scan([]byte("user@-example.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for domain label starting with dash, want 0", len(findings))
	}
}

func TestEmailDetector_DomainLabelEndsWithDash(t *testing.T) {
	t.Parallel()

	d := NewEmail()
	// Domain label ending with '-' (before dot) is invalid per RFC 5321.
	findings := d.Scan([]byte("user@example-.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for domain label ending with dash, want 0", len(findings))
	}
}

func TestEmailDetector_DomainStartsWithDot(t *testing.T) {
	t.Parallel()

	// A domain that starts with '.' has an empty first label, so "user@.com"
	// is not an address: there is no domain name, only a TLD. Rejecting it
	// mirrors the rule that the local part must not start with '.'.
	d := NewEmail()
	tests := []struct {
		name  string
		input string
	}{
		{name: "TLD only after the at sign", input: "user@.com"},
		{name: "leading dot before a full domain", input: "user@.example.com"},
		{name: "second at sign followed by a dot", input: "0.AA@.AA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if findings := d.Scan([]byte(tt.input)); len(findings) != 0 {
				t.Errorf("Scan(%q) = %q, want no findings", tt.input, tt.input[findings[0].Start:findings[0].End])
			}
		})
	}
}

func TestEmailExactDocumentedScores(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		text  string
		score float64
	}{{"alice@example.com", 1}, {"alice@example.zzzz", 0.8}, {"alice@ex..ample.com", 0.9}} {
		t.Run(fixture.text, func(t *testing.T) {
			t.Parallel()
			findings := NewEmail().Scan([]byte(fixture.text))
			if len(findings) != 1 || findings[0].Confidence != fixture.score {
				t.Fatalf("got %v want exact score %.17g", findings, fixture.score)
			}
		})
	}
}

func TestEmailAdjacentMatches(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"0@0..AA+@0.AA", "a@b..com+c@d.com", "a@b.com+c@d.com+e@f.com"} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			findings := NewEmail().Scan([]byte(input))
			end := 0
			for _, finding := range findings {
				if finding.Start != end {
					t.Fatalf("gap or overlap: start=%d, previous end=%d", finding.Start, end)
				}
				end = finding.End
			}
			if end != len(input) {
				t.Fatalf("unmasked suffix at %d of %d", end, len(input))
			}
		})
	}
}

// Independent finite alphabets target boundary mutants missed by ordinary prose.
func TestDetectorByteAlphabets(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		alnum := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", rune(b))
		if isLocalPartChar(b) != (alnum || strings.ContainsRune(".+-_", rune(b))) {
			t.Fatalf("local alphabet %x", b)
		}
		if isDomainChar(b) != (alnum || strings.ContainsRune(".-", rune(b))) {
			t.Fatalf("domain alphabet %x", b)
		}
	}
	for _, domain := range []string{"", "a", "-a", "a-b", "a-.b", "a.-b", "a.b", "a..b", ".a", "a."} {
		want := false
		for label := range strings.SplitSeq(domain, ".") {
			want = want || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-")
		}
		// The helper's contract only covers leading '-' and '-' adjacent to dots;
		// trailing domain hyphens are removed by findDomainEnd.
		if hasInvalidLabelBoundary([]byte(domain)) != want {
			t.Fatalf("label boundary %q", domain)
		}
		if hasConsecutiveDots([]byte(domain)) != strings.Contains(domain, "..") {
			t.Fatalf("dots %q", domain)
		}
	}
}

func TestGitRemoteContexts(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"github.com", "gitlab.com", "code.example.org"} {
		for _, path := range []string{"org/repo.git", "repo", "/srv/project.git"} {
			input := "git clone git@" + host + ":" + path
			if got := NewEmail().Scan([]byte(input)); len(got) != 0 {
				t.Errorf("SSH remote treated as email: %s", input)
			}
		}
		if got := NewEmail().Scan([]byte("contact git@" + host)); len(got) != 1 {
			t.Error("ordinary mailbox lost")
		}
	}
}

func TestEmailDomainValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		domain string
		valid  bool
	}{{"example.com", true}, {"example.museum", true}, {"-example.com", false}, {"example-.com", false}, {"example.c", false}, {"example.c0", false}, {".com", false}} {
		_, valid := validateTLD([]byte(tc.domain))
		if valid != tc.valid {
			t.Fatal(tc.domain, valid)
		}
	}
}

const emailUserinfoFixture = "alice@example.com"

func TestEmailIgnoresURLUserinfo(t *testing.T) {
	t.Parallel()
	d := NewEmail()
	for _, tc := range []struct {
		input, matched string
		count          int
	}{
		// #nosec G101 -- Public synthetic DSN used to test URL userinfo handling.
		{input: "postgres://app:s3cr3t@db.example/orders", count: 0},
		{input: "dsn=postgres://s3cr3t@db.example:5432/orders", count: 0},
		{input: "redis://:s3cr3t@cache.example.com:6379", count: 0},
		{input: "https://user.name@example.com/path", count: 0},
		{input: "contact alice@example.com about postgres://app:pw@db.example", matched: emailUserinfoFixture, count: 1},
		{input: "see:alice@example.com", matched: emailUserinfoFixture, count: 1},
		{input: "mailto:alice@example.com", matched: emailUserinfoFixture, count: 1},
		{input: "path //alice@example.com", matched: emailUserinfoFixture, count: 1},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			assertScanMatch(t, d, tc.input, tc.count, tc.matched)
		})
	}
}

func TestEmailFullWidthAtSign(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ input, want string }{
		{"連絡先: bob＠example.com まで", "bob＠example.com"},
		{"bob＠example.com, alice@example.org", "bob＠example.com"},
		{"＠example.com", ""},
		{"bob＠", ""},
		{"bob＠localhost", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := ""
			if findings := NewEmail().Scan([]byte(tc.input)); len(findings) > 0 {
				got = tc.input[findings[0].Start:findings[0].End]
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEmailFullWidthDomainStart(t *testing.T) {
	t.Parallel()
	input := "bob＠x.jp"
	if got := NewEmail().Scan([]byte(input)); len(got) != 1 || input[got[0].Start:got[0].End] != input {
		t.Fatalf("Scan(%q) = %+v", input, got)
	}
}
