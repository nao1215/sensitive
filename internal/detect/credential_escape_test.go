package detect

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestMixedCredentialEscapeLayers(t *testing.T) {
	t.Parallel()
	input := `password=firstFixture body={\"token\":\"secondFixture\"}`
	findings := (&Credential{}).Scan([]byte(input))
	if len(findings) != 2 || input[findings[0].Start:findings[0].End] != firstCredentialFixture || input[findings[1].Start:findings[1].End] != "secondFixture" {
		t.Fatalf("mixed layers lost or duplicated a value: %+v", findings)
	}
}

func TestDetectorCredentialEscapesAndBoundariesProperty(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for n := range 16 {
		secret := fmt.Sprintf("opaqueBoundary%02dFixture", n)
		inputs := make([]string, 0, 18)
		inputs = append(inputs, "map[password:"+secret+" tail user:bob]", "{Password:head "+secret+" tail}", "password=`head "+secret+" tail`", "password := "+secret, "{DSN:{Scheme:https Opaque: User:bob:"+secret+" Host:example.com Path:/x}}")
		for _, prefix := range []string{"[]", "[abc]", ",", ")", "[REDACTED]]", "[REDACTED][REDACTED]"} {
			inputs = append(inputs, credentialAssignmentFixture+prefix+secret)
		}
		escaped := `{"password":"` + secret + `"}`
		for range 4 {
			inputs = append(inputs, escaped)
			escaped = strconv.Quote(escaped)
		}
		for _, quote := range []string{`\x22`, `\u0022`} {
			inputs = append(inputs, "{"+quote+passwordKeyFixture+quote+":"+quote+secret+quote+"}")
		}
		for _, input := range inputs {
			if got := maskCredentialFindings(input, scanner.Scan([]byte(input))); strings.Contains(got, secret) {
				t.Errorf("boundary visible: %q => %q", input, got)
			}
		}
	}
}

func TestDetectorEscapedCredentialFragments(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, secret := range []string{"opaqueHead\"opaqueTail", `opaqueHead\opaqueTail`, "opaqueHead\nopaqueTail", "[REDACTED]opaqueTail"} {
		// Each suffix must disappear even when the secret contains a quote or bracket.
		input := `{"password":` + strconv.Quote(secret) + `}`
		for range 3 {
			got := maskCredentialFindings(input, scanner.Scan([]byte(input)))
			if strings.Contains(got, "opaqueHead") || strings.Contains(got, "opaqueTail") {
				t.Errorf("escaped secret fragment retained: %q => %q", input, got)
			}
			input = strconv.Quote(input)
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
			input = fmt.Sprintf(verb, url.Values{passwordKeyFixture: {secret, secret}})
			got := maskCredentialFindings(input, scanner.Scan([]byte(input)))
			if strings.Contains(got, "opaqueHead") || strings.Contains(got, "opaqueTail") {
				t.Errorf("slice fragment retained: %q => %q", input, got)
			}
		}
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
			findings := (&Credential{}).ScanViews(raw, []byte(plain), positions)
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
	got := (&Credential{}).ScanViews(input, input, nil)
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
		findings := (&Credential{}).ScanViews([]byte(raw), []byte(decoded), positions)
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

func TestCredentialQuotesBoundaryMap(t *testing.T) {
	t.Parallel()
	for _, escaped := range []string{`\"`, `\x22`, `\u0022`} {
		raw := []byte("before" + escaped + "after")
		decoded, positions := credentialQuotes(raw)
		if string(decoded) != `before"after` || positions[6] != 6 || positions[7] != 6+len(escaped) || positions[len(decoded)] != len(raw) {
			t.Fatal(escaped, string(decoded), positions)
		}
	}
}
