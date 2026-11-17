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
