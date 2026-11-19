package detect

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestCredentialContainerBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input string
		want  string
	}{
		{`password:[one [nested] tail] public:kept`, `one [nested] tail`},
		{`password:[]string{"one\"tail", "two"} public:kept`, `"one\"tail", "two"`},
		{`password:[unterminated`, `unterminated`},
		{`password:["unfinished\`, `"unfinished\`},
	} {
		got := (&Credential{}).Scan([]byte(tc.input))
		if len(got) != 1 || tc.input[got[0].Start:got[0].End] != tc.want {
			t.Errorf("container %q: %+v", tc.input, got)
		}
	}
}

func TestCredentialLineAndBlockBoundaries(t *testing.T) {
	t.Parallel()
	const scalar = "fixture"
	for _, tc := range []struct{ input, want string }{
		{"password=fixture\npublic=kept", scalar},
		{"password=fixture\r\npublic=kept", scalar},
		{`password=fixture" public=kept`, scalar},
		{"Authorization: Token fixture\npublic=kept", scalar},
		{"Authorization: Token fixture\r\npublic=kept", scalar},
		{"password: |", "|"},
		{"password: |literal", "|literal"},
		{"password: |\n  fixture", "|\n  fixture"},
	} {
		got := (&Credential{}).Scan([]byte(tc.input))
		if len(got) != 1 || tc.input[got[0].Start:got[0].End] != tc.want {
			t.Errorf("boundary %q: %+v", tc.input, got)
		}
	}
}

func TestCredentialAnonymousTypeBoundaries(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`password:struct { Raw string }{Raw:"opaqueAnonymousFixture"} public:kept`,
		`password:[]struct { Raw string }{{Raw:"opaqueAnonymousFixture"}} public:kept`,
		`password:map[string]struct { Raw string }{"item":{Raw:"opaqueAnonymousFixture"}} public:kept`,
	} {
		got := (&Credential{}).Scan([]byte(input))
		if len(got) != 1 || !strings.Contains(input[got[0].Start:got[0].End], "opaqueAnonymousFixture") || strings.Contains(input[got[0].Start:got[0].End], "public:kept") || strings.Contains(input[got[0].Start:got[0].End], "Raw string") {
			t.Errorf("anonymous type was mistaken for its value: %+v", got)
		}
	}
}

func TestDetectorCredentialGoRenderingProperty(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for n := range 16 {
		secret := fmt.Sprintf("opaqueGo%02dFixture", n)
		for _, value := range []any{secret, []byte(secret), []any{secret}, []string{secret}, map[string]string{"access": secret}, sql.NullString{String: secret, Valid: true}, sql.Null[string]{V: secret, Valid: true}, struct{ Raw string }{secret}, []struct{ Raw string }{{secret}}, credentialPropertyString(secret)} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
				for _, input := range []string{fmt.Sprintf(verb, map[string]any{passwordKeyFixture: value}), fmt.Sprintf(verb, map[string]any{authorizationHeaderFixture: value}), fmt.Sprintf(verb, struct{ Password any }{value})} {
					// Plain struct %v and %q omit field names; no credential context survives.
					if !strings.Contains(strings.ToLower(input), passwordKeyFixture) && !strings.Contains(input, authorizationHeaderFixture) {
						continue
					}
					findings := scanner.Scan([]byte(input))
					got := maskCredentialFindings(input, findings)
					hexBytes := fmt.Sprintf("%#v", []byte(secret))
					checkCredentialByteCoverage(t, input, secret, findings)
					checkCredentialByteCoverage(t, input, hexBytes[strings.IndexByte(hexBytes, '{')+1:len(hexBytes)-1], findings)
					checkCredentialByteCoverage(t, input, strings.Trim(fmt.Sprintf("%v", []byte(secret)), "[]"), findings)
					if strings.Contains(got, secret) || strings.Contains(got, hexBytes[strings.IndexByte(hexBytes, '{')+1:len(hexBytes)-1]) || strings.Contains(got, strings.Trim(fmt.Sprintf("%v", []byte(secret)), "[]")) {
						t.Errorf("Go value visible: %q => %q", input, got)
					}
				}
			}
		}
		for _, input := range []string{`password:main.Password("` + secret + `")`, `password:[]interface {}{"` + secret + `"}`, `password:map[string]string{"access":"` + secret + `"}`, `password:sql.NullString{String:"` + secret + `", Valid:true}`} {
			if got := maskCredentialFindings(input, scanner.Scan([]byte(input))); strings.Contains(got, secret) {
				t.Errorf("typed value visible: %q => %q", input, got)
			}
		}
	}
}

func TestCredentialNamedIdentifierProperty(t *testing.T) {
	t.Parallel()
	for n := range 16 {
		value := strconv.Quote(fmt.Sprintf("opaqueNamed%02dFixture", n))
		for _, name := range []string{"main.Password", "main.Password_Value", "main.秘密", "example_test.Token_T"} {
			prefix := "password:" + name + "("
			input := prefix + value + ") public:kept"
			got := (&Credential{}).Scan([]byte(input))
			if len(got) != 1 || got[0].Start != len(prefix) || got[0].End != len(prefix)+len(value) {
				t.Fatalf("named identifier %s did not isolate its value: %+v", name, got)
			}
		}
	}
}

func TestCredentialOuterBoundaryProperty(t *testing.T) {
	t.Parallel()
	const (
		scalar     = "fixture"
		publicLine = "\npublic=kept"
		formatted  = "head fixture tail"
		publicJSON = `","public":"kept"}`
	)

	for n := range 16 {
		secret := fmt.Sprintf("opaqueOuter%02dFixture", n)
		for _, tc := range []struct{ before, value, after string }{
			{credentialAssignmentFixture, scalar, " public=kept"},
			{"password := ", scalar, publicLine},
			{"map[password:", formatted, " public:kept]"},
			{"{Password:", formatted, " Public:kept}"},
			{"password=`", formatted, "`\npublic=kept"},
			{`{"password":"`, scalar, publicJSON},
			{`map[string]string{"password":"`, scalar, publicJSON},
			{`password:[]string{`, `"fixture", "second"`, `} public:kept`},
			{`password:main.Secret_Value(`, `"fixture"`, `) public:kept`},
			{`password:struct { Raw string }{`, `Raw:"fixture"`, `} public:kept`},
			{"Authorization: Token ", "fixture, Basic second", publicLine},
			{"Authorization: Digest ", `username="fixture", response="second"`, publicLine},
			{`{"Authorization":"Token `, "fixture, Basic second", publicJSON},
			{`map[Authorization:[`, "Token fixture, Basic second", `] public:kept]`},
			{`body={\"password\":\"`, scalar, `\",\"public\":\"kept\"}`},
			{credentialAssignmentFixture, "[]fixture", publicLine},
			{credentialAssignmentFixture, "[REDACTED]]fixture", publicLine},
		} {
			value := strings.ReplaceAll(tc.value, scalar, secret)
			input := tc.before + value + tc.after
			want := tc.before + strings.Repeat("*", len(value)) + tc.after
			if got := maskCredentialFindings(input, (&Credential{}).Scan([]byte(input))); got != want {
				t.Fatalf("credential consumed adjacent public context: %q => %q; want %q", input, got, want)
			}
		}
	}
}

func TestCredentialLongFmtKeyProperty(t *testing.T) {
	t.Parallel()
	for _, length := range []int{1, 14, 15, 16, 17, 32, 128} {
		key := strings.Repeat("service_", length) + passwordKeyFixture
		for _, value := range []string{"head opaqueLongFixture tail", "opaqueLongFixture with several words"} {
			for _, before := range []string{"map[" + key + ":", "map[public:" + strings.Repeat("x", length*16) + " password:", "{Token:first Password:", "{Public:kept\nPassword:"} {
				after := " public:kept]"
				input := before + value + after
				end := len(value)
				if strings.Contains(before, "\n") {
					end = strings.IndexByte(value, ' ')
				}
				want := strings.Replace(before, "Token:first", "Token:*****", 1) + strings.Repeat("*", end) + value[end:] + after
				if got := maskCredentialFindings(input, (&Credential{}).Scan([]byte(input))); got != want {
					t.Fatalf("long credential key lost its fmt context: %q => %q; want %q", input, got, want)
				}
			}
		}
	}
}

func TestDetectorCredentialAssignmentDelimiters(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, text := range []string{"failure (password=opaque)", "fields [token=opaque]", "record <secret=opaque>", `{"Authorization":"Bearer opaque"}`} {
		got := maskCredentialFindings(text, scanner.Scan([]byte(text)))
		if want := strings.Replace(text, "opaque", "******", 1); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}

func TestDetectorCredentialObjectSyntaxStillProtectsPasswords(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, text := range []string{`password=Example@abcdef12`, `token="Example@abcdef12"`, `secret=Token{abcdef12`, `token=Example@nothex`} {
		if len(scanner.Scan([]byte(text))) != 1 {
			t.Errorf("credential was missed: %s", text)
		}
	}
}

func TestDetectorCredentialRedactedCollections(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, content := range []string{`"[REDACTED]"`, `"[REDACTED]", "[REDACTED]"`, `["[REDACTED]"]`} {
		input := `{"X-Token":[` + content + `]}`
		if got := scanner.Scan([]byte(input)); len(got) != 0 {
			t.Errorf("already masked collection: %+v", got)
		}
		for _, tail := range []string{`,"fixtureSecret"`, `,"[REDACTED]fixtureSecret"`} {
			input := `{"X-Token":[` + content + tail + `]}`
			if strings.Contains(maskCredentialFindings(input, scanner.Scan([]byte(input))), "fixtureSecret") {
				t.Error("marker collection hid a real credential")
			}
		}
	}
}

func TestCredentialShortAndEmptyValues(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{credentialAssignmentFixture, "token=", "token: ", "password : ", "'password':", `"password":`, "Authorization: Token "} {
		for _, quote := range []string{"", "\"", "'", "`"} {
			if strings.HasPrefix(prefix, "Authorization:") && quote != "" {
				continue
			}
			input := prefix + quote + quote
			if got := (&Credential{}).Scan([]byte(input)); len(got) != 0 {
				t.Fatalf("empty credential: %q: %+v", input, got)
			}
			for _, value := range []string{"a", "Z", "0", "_", "-"} {
				input = prefix + quote + value + quote
				got := (&Credential{}).Scan([]byte(input))
				if len(got) != 1 || got[0].Start != len(prefix)+len(quote) || got[0].End != len(prefix)+len(quote)+len(value) || input[got[0].Start:got[0].End] != value {
					t.Fatalf("short credential: %q: %+v", input, got)
				}
			}
		}
	}
	for _, form := range []string{"[]", "main.Secret()"} {
		input := "password:" + form
		if got := (&Credential{}).Scan([]byte(input)); len(got) != 0 {
			t.Fatalf("empty composite credential: %q: %+v", input, got)
		}
	}
}

func TestCredentialTruncatedRenderingProperty(t *testing.T) {
	t.Parallel()
	const secret = "opaqueTruncationFixture"
	forms := []string{
		`password="` + secret + `\"tail\\" public=kept`,
		`password='` + secret + `\'tail\\' public=kept`,
		"password=`" + secret + "\\` public=kept",
		"map[password:" + secret + " public:retained]",
		"map[password:" + secret + " \t public:retained]",
		`password:struct { Value string }{"` + secret + `"}`,
		`password:[]interface {}{"` + secret + `"}`,
		"Authorization: Token " + secret + "\\",
		`Authorization: Digest response="` + secret + `\"tail\\"`,
		"Authorization: Token " + secret + ", \t Basic anotherFixture",
		"password: |\n  " + secret + "\n   \npublic: kept",
		"password: |\r\n  " + secret + "\r\n   \r\npublic: kept",
	}
	for _, form := range forms {
		for end := 0; end <= len(form); end++ {
			input := form[:end]
			findings := (&Credential{}).Scan([]byte(input))
			for _, finding := range findings {
				if finding.Start < 0 || finding.End > len(input) || finding.Start >= finding.End {
					t.Fatalf("truncated rendering has invalid original offsets: %q %+v", input, findings)
				}
			}
			if strings.Contains(input, secret) && strings.Contains(maskCredentialFindings(input, findings), secret) {
				t.Fatalf("truncated rendering exposed complete value: %q %+v", input, findings)
			}
		}
	}
}

func TestCredentialContainerQuoteOwnership(t *testing.T) {
	t.Parallel()
	for _, quoted := range []string{`"a]b"`, "'a]b'", "`a]b`"} {
		text := quoted + ", [child]] public"
		if got := credentialContainerEnd([]byte(text), 0, ']'); got != len(quoted+", [child]") {
			t.Fatal(text, got)
		}
	}
}

func TestCredentialQuotedAssignmentKeys(t *testing.T) {
	t.Parallel()
	for _, quote := range []string{`"`, "'"} {
		text := quote + "service.password" + quote + ":"
		if got := assignmentKey([]byte(text), len(text)-1); string(got) != "service.password" {
			t.Fatal(text, string(got))
		}
	}
}

func TestCredentialCustomMultiwordKey(t *testing.T) {
	t.Parallel()
	detector := &Credential{MatchKey: func(key string) bool { return key == "custom phrase" }}
	text := "custom phrase = opaqueFixture public=kept"
	got := detector.Scan([]byte(text))
	if len(got) != 1 || text[got[0].Start:got[0].End] != "opaqueFixture" {
		t.Fatalf("multiword custom key: %+v", got)
	}
}

func TestCredentialObjectReferenceHexEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		value string
		match string
		count int
	}{
		{name: "one hexadecimal digit", value: "Thing@f", count: 0},
		{name: "sixteen hexadecimal digits", value: "Thing@0123456789abcdef", count: 0},
		{name: "seventeen hexadecimal digits", value: "Thing@0123456789abcdef0", match: "Thing@0123456789abcdef0", count: 1},
		{name: "missing identity", value: "Thing@", match: "Thing@", count: 1},
		{name: "non-hexadecimal identity", value: "Thing@g", match: "Thing@g", count: 1},
		{name: "quoted string", value: `"Thing@f"`, match: "Thing@f", count: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertDetectorScan(t, &Credential{}, "token="+tc.value, tc.count, tc.match, 0)
		})
	}
}

func TestCredentialMismatchedContainerEnds(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"[} value]", "{] value}", "(} value)", `["}" value]`, "[{} value]"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			assertDetectorScan(t, &Credential{}, "password="+value+" next=ok", 1, value[1:len(value)-1], 0)
		})
	}
}

func TestCredentialAssignmentOperators(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, tc := range []struct{ text, want string }{
		{`{"api_token" => "opaque12"}`, `{"api_token" => "********"}`},
		{`{:password=>"opaque12"}`, `{:password=>"********"}`},
		{`    [api_token] => opaque12`, `    [api_token] => ********`},
		{`API_TOKEN ::= "opaque12"`, `API_TOKEN ::= "********"`},
		{`API_TOKEN :::= "opaque12"`, `API_TOKEN :::= "********"`},
		{`API_TOKEN ?= "opaque12"`, `API_TOKEN ?= "********"`},
		{`$apiToken .= "opaque12"`, `$apiToken .= "********"`},
		{`token ||= "opaque12"`, `token ||= "********"`},
		{`password += "opaque12"`, `password += "********"`},
		{`var apiToken string = "opaque12"`, `var apiToken string = "********"`},
		{`val apiToken: String = "opaque12"`, `val apiToken: String = "********"`},
		{`let token: &str = "opaque12";`, `let token: &str = "********";`},
		{`token == "opaque12"`, `token == "********"`},
	} {
		if got := maskCredentialFindings(tc.text, scanner.Scan([]byte(tc.text))); got != tc.want {
			t.Errorf("Scan(%q) masked to %q, want %q", tc.text, got, tc.want)
		}
	}
}

func TestCredentialOperatorLookalikesStayVisible(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, text := range []string{
		`if token != nil { return }`,
		`items[3] => done`,
		`name string = "visible"`,
		`string = "visible"`,
		`items[] = visible`,
		`list] = visible`,
	} {
		if got := scanner.Scan([]byte(text)); len(got) != 0 {
			t.Errorf("Scan(%q) = %+v, want none", text, got)
		}
	}
}

func TestCredentialJSessionIDPathParameter(t *testing.T) {
	t.Parallel()
	d := &Credential{}
	for input, want := range map[string]string{
		"GET /app;jsessionid=ABCDEF0123456789?x=1 HTTP/1.1": "ABCDEF0123456789",
		"session=abc?def ok": "abc?def",
	} {
		findings := d.Scan([]byte(input))
		if len(findings) != 1 || input[findings[0].Start:findings[0].End] != want {
			t.Errorf("Scan(%q) = %+v, want %q", input, findings, want)
		}
	}
}
