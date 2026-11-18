package detect

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

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

// Exercise the public detector entry point independently of root dispatch.
const (
	authorizationHeaderFixture  = "Authorization"
	passwordKeyFixture          = "password"
	bearerSchemeFixture         = "Bearer"
	tokenSchemeFixture          = "Token"
	basicSchemeFixture          = "Basic"
	firstCredentialFixture      = "firstFixture"
	credentialAssignmentFixture = "password="
)

type credentialPropertyString string

func maskCredentialFindings(input string, findings []Finding) string {
	data := []byte(input)
	for _, finding := range findings {
		for at := finding.Start; at < finding.End; at++ {
			data[at] = '*'
		}
	}
	return string(data)
}

func TestDetectorCredentialSecretSpans(t *testing.T) {
	t.Parallel()
	const forgottenFixture = "forgotten"
	for _, tc := range []struct{ text, secret string }{
		{`password=forgotten-pass host=db.example database=orders`, "forgotten-pass"},
		{`{"apiKey":"a forgotten value","count":17}`, "a forgotten value"},
		{`Authorization: Bearer pretend-bearer-token`, "pretend-bearer-token"},
		{`Authorization: Basic ZmFrZTpmaWN0aXRpb3Vz`, "ZmFrZTpmaWN0aXRpb3Vz"},
		{`Cookie: session=forgotten; theme=dark`, "session=forgotten; theme=dark"},
		{`postgres://reader:fake%2Fpass%40word@db.example/orders?sslmode=require`, "fake%2Fpass%40word"},
		{`mysql://reader:forgotten@db.example/orders`, forgottenFixture},
		{`reader:forgotten@tcp(db.example:3306)/orders`, forgottenFixture},
		{`mongodb+srv://reader:forgotten@db.example/orders`, forgottenFixture},
		{`redis://:forgotten@db.example/0`, forgottenFixture},
		{`amqp://reader:forgotten@mq.example/vhost`, forgottenFixture},
		{`https://bucket.example/file?X-Amz-Signature=pretend-signature&expires=17`, "pretend-signature"},
		{`https://blob.example/file?sig=pretend%2Bsignature%3D&sv=2025`, "pretend%2Bsignature%3D"},
		{`AccountName=demo;AccountKey=pretend-storage-key==;EndpointSuffix=core.windows.net`, "pretend-storage-key=="},
		{`{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n"}`, `-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n`},
		{`aws_secret_access_key=pretend-key`, "pretend-key"},
		{`TWILIO_AUTH_TOKEN=pretend-auth-token`, "pretend-auth-token"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			scanner := &Credential{}
			got := scanner.Scan([]byte(tc.text))
			start := strings.Index(tc.text, tc.secret)
			if len(got) != 1 || got[0].Start != start || got[0].End != start+len(tc.secret) {
				t.Fatalf("got %v, want secret span [%d,%d)", got, start, start+len(tc.secret))
			}
			if masked := maskCredentialFindings(tc.text, got); masked != strings.Replace(tc.text, tc.secret, strings.Repeat("*", len(tc.secret)), 1) {
				t.Fatal(masked)
			}
		})
	}
}

func TestDetectorCredentialNegatives(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, text := range []string{"passwordless=true", "token_count=17", "https://example.com/db", "reader@db.example", credentialAssignmentFixture, `password="[REDACTED]"`, `sigaction=normal`, `classification:public`} {
		if got := scanner.Scan([]byte(text)); len(got) != 0 {
			t.Errorf("%q: %v", text, got)
		}
	}
}

func TestDetectorCredentialAWSContextDoesNotDuplicateAssignment(t *testing.T) {
	t.Parallel()
	value := "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUgQx2A9cF6"
	text := "AKIAIOSFODNN7EXAMPLE aws_secret_access_key=" + value
	got := (&Credential{}).Scan([]byte(text))
	if len(got) != 1 || text[got[0].Start:got[0].End] != value {
		t.Fatalf("expected one credential span, got %v", got)
	}
}

// Every original credential byte must belong to a finding, even when removing
// only a prefix would already make a whole-string leak check pass.
func checkCredentialByteCoverage(t *testing.T, input, needle string, findings []Finding) {
	t.Helper()
	for offset := 0; offset < len(input); {
		at := strings.Index(input[offset:], needle)
		if at < 0 {
			return
		}
		start := offset + at
		end := start + len(needle)
		for i := start; i < end; i++ {
			covered := false
			for _, finding := range findings {
				if finding.Start <= i && i < finding.End {
					covered = true
					break
				}
			}
			if !covered {
				t.Fatalf("credential byte %d is not covered: %q %+v", i, input, findings)
			}
		}
		offset = end
	}
}

func TestCredentialNormalizedViewSpans(t *testing.T) {
	t.Parallel()
	// #nosec G101 -- Synthetic credential used only to verify offsets.
	const secret = "opaqueViewFixture"
	for _, plain := range []string{credentialAssignmentFixture + secret, "public=kept password=" + secret} {
		for encoded := -1; encoded < len(plain); encoded++ {
			var raw []byte
			positions := make([]int, 0, len(plain)+1)
			for i := range len(plain) {
				positions = append(positions, len(raw))
				if i == encoded {
					raw = append(raw, fmt.Sprintf("%%%02X", plain[i])...)
				} else {
					raw = append(raw, plain[i])
				}
			}
			positions = append(positions, len(raw))
			findings := (&Credential{}).scanView(View{Raw: raw, Data: []byte(plain), Positions: positions})
			at := strings.Index(plain, secret)
			found := false
			for _, f := range findings {
				if f.Start == positions[at] && f.End == positions[at+len(secret)] {
					found = true
				}
			}
			if !found {
				t.Fatalf("normalized view lost original value span at encoding %d: %q %+v", encoded, string(raw), findings)
			}
		}
	}
	input := []byte(credentialAssignmentFixture + secret)
	got := (&Credential{}).scanView(View{Raw: input, Data: input})
	if len(got) != 1 || string(input)[got[0].Start:got[0].End] != secret {
		t.Fatalf("identity view: %+v", got)
	}
}

func TestCredentialRawAndNormalizedOwnership(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"password=firstFixture", "password=first%20Fixture", "https://user:first%2FFixture@host/path", "https://user:first%40Fixture@host/path"} {
		raw := prefix + " token%3DsecondFixture"
		decoded, err := url.PathUnescape(raw)
		if err != nil {
			t.Fatal(err)
		}
		var positions []int
		for at := 0; at < len(raw); {
			positions = append(positions, at)
			if raw[at] == '%' {
				at += 3
			} else {
				at++
			}
		}
		positions = append(positions, len(raw))
		findings := (&Credential{}).scanView(View{Raw: []byte(raw), Data: []byte(decoded), Positions: positions})
		first := firstCredentialFixture
		if strings.Contains(prefix, "%20") {
			first = "first%20Fixture"
		}
		if strings.Contains(prefix, "%2F") {
			first = "first%2FFixture"
		}
		if strings.Contains(prefix, "%40") {
			first = "first%40Fixture"
		}
		if len(findings) != 2 {
			t.Fatalf("raw/normalized overlap duplicated or hid values: %q: %+v", raw, findings)
		}
		for i, value := range []string{first, "secondFixture"} {
			at := strings.Index(raw, value)
			if findings[i].Start != at || findings[i].End != at+len(value) || raw[findings[i].Start:findings[i].End] != value {
				t.Fatalf("raw ownership: %q: %+v", raw, findings)
			}
		}
	}
}

func TestCredentialSkipsUUIDIdempotencyTokens(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want int
	}{
		{`"clientToken": "129CAF40-59BF-4E49-8324-ED4F25010DCC"`, 0},
		{`"ClientToken": "129caf40-59bf-4e49-8324-ed4f25010dcc"`, 0},
		{`idempotency_token=129caf40-59bf-4e49-8324-ed4f25010dcc`, 0},
		{`"clientToken": "129CAF40-59BF-4E49-8324-ED4F25010DCCX"`, 1},
		{`"clientToken": "129caf40-59bf-4e49-8324-ed4f25010dcc-retry"`, 1},
		{`"authToken": "129CAF40-59BF-4E49-8324-ED4F25010DCC"`, 1},
	} {
		if got := (&Credential{}).Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("%q: got %v, want %d findings", tc.text, got, tc.want)
		}
	}
}

func TestCredentialAssignsKey(t *testing.T) {
	t.Parallel()
	if AssignsKey(&Email{}, []byte("password: x"), len("password")) {
		t.Fatal("email detector assigned a key")
	}
	d := &Credential{}
	for text, want := range map[string]bool{"password: x": true, "db_pass: x": true, "field12: x": false, "token: TokenStore@1a2b3c": false, "token: abc": true} {
		if got := AssignsKey(d, []byte(text), strings.IndexByte(text, ':')); got != want {
			t.Errorf("AssignsKey(%q) = %v, want %v", text, got, want)
		}
	}
}
