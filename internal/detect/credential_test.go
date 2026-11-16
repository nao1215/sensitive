package detect

import (
	"bytes"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestURLPasswordFastPathDifferential(t *testing.T) {
	t.Parallel()
	fragments := []string{"worker completed request reference=example", "postgres://reader:fake@db.example/orders", "reader:fake@tcp(db.example:3306)/orders", "secret://token:fake@host/path", "redis://user:p%40ss@host", "a@b", "://", "@tcp(", "@unix(", "host:123", "token=value"}
	for b := range 256 {
		for _, left := range fragments {
			for _, right := range fragments {
				data := []byte(left + string(rune(b)) + right)
				got, want := urlPasswords(data), referenceURLPasswords(data)
				if !slices.EqualFunc(got, want, func(a, b Finding) bool {
					return a.Start == b.Start && a.End == b.End && a.Confidence == b.Confidence && a.RawValue == b.RawValue
				}) {
					t.Fatalf("differential mismatch at separator %d", b)
				}
			}
		}
	}
}

func referenceURLPasswords(data []byte) []Finding {
	var out []Finding
	for start := 0; start < len(data); {
		if referenceURLDelimiter(data[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(data) && !referenceURLDelimiter(data[end]) {
			end++
		}
		segment := data[start:end]
		if scheme := bytes.Index(segment, []byte("://")); scheme >= 0 {
			start += scheme + len("://")
			segment = data[start:end]
			if tail := bytes.IndexAny(segment, "/?#"); tail >= 0 {
				segment = segment[:tail]
			}
		} else if !bytes.Contains(segment, []byte("@tcp(")) && !bytes.Contains(segment, []byte("@unix(")) {
			start = end
			continue
		}
		at := bytes.LastIndexByte(segment, '@')
		if at >= 0 {
			colon := bytes.IndexByte(segment[:at], ':')
			if colon >= 0 && !bytes.ContainsAny(segment[:colon], "/?#@") {
				secret := start + colon + 1
				stop := start + at
				if secret < stop && string(data[secret:stop]) != "[REDACTED]" {
					out = append(out, credentialFinding(data, secret, stop))
				}
			}
		}
		start = end
	}
	return out
}

func referenceURLDelimiter(b byte) bool { return strings.ContainsRune(" \t\r\n\"'<>", rune(b)) }

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

func TestCredentialLongUnknownKey(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("field", 8) + "=opaque-value password=actual-test-password"
	got := (&Credential{}).Scan([]byte(text))
	if len(got) != 1 || text[got[0].Start:got[0].End] != "actual-test-password" {
		t.Fatal("unknown long key masked or following password lost")
	}
}

func TestProxyAuthorizationCredentials(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"Proxy-Authorization", "proxy_authorization", "PROXYAUTHORIZATION"} {
		input := key + ": Basic dXNlcjpodW50ZXIy"
		got := (&Credential{}).Scan([]byte(input))
		if len(got) != 1 || got[0].RawValue != "dXNlcjpodW50ZXIy" || !SensitiveCredentialKey(key) {
			t.Fatalf("credentials not masked: %v", got)
		}
	}
}

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
		if len(got) != 1 || got[0].RawValue != tc.want {
			t.Errorf("container %q: %+v", tc.input, got)
		}
	}
}

func TestMixedCredentialEscapeLayers(t *testing.T) {
	t.Parallel()
	input := `password=firstFixture body={\"token\":\"secondFixture\"}`
	findings := (&Credential{}).Scan([]byte(input))
	if len(findings) != 2 || findings[0].RawValue != "firstFixture" || findings[1].RawValue != "secondFixture" {
		t.Fatalf("mixed layers lost or duplicated a value: %+v", findings)
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
		if len(got) != 1 || got[0].RawValue != tc.want {
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
		if len(got) != 1 || !strings.Contains(got[0].RawValue, "opaqueAnonymousFixture") || strings.Contains(got[0].RawValue, "public:kept") || strings.Contains(got[0].RawValue, "Raw string") {
			t.Errorf("anonymous type was mistaken for its value: %+v", got)
		}
	}
}

// Exercise the public detector entry point independently of root dispatch.
const authorizationHeaderFixture = "Authorization"

type credentialPropertyString string

func TestDetectorAuthorizationSchemeProperty(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for n := range 24 {
		secret := fmt.Sprintf("opaqueAuth%02dFixture", n)
		for _, scheme := range []string{"Token", "Negotiate", "Digest", "AWS4-HMAC-SHA256", "Bearer", "Basic", fmt.Sprintf("Scheme%d!#$%%&'*+-.^_`|~", n)} {
			for _, space := range []string{" ", "\t", "   "} {
				credential := secret
				if scheme == "Digest" {
					credential = `username="fixture", realm="example", response="` + secret + `"`
				}
				if scheme == "AWS4-HMAC-SHA256" {
					credential = "Credential=fixture, SignedHeaders=host, Signature=" + secret
				}
				value := scheme + space + credential
				for count := 1; count <= 3; count++ {
					list := strings.TrimSuffix(strings.Repeat(value+", ", count), ", ")
					for _, input := range []string{"Authorization: " + list, "Proxy-Authorization: " + list, `{"msg":` + strconv.Quote("Authorization: "+list) + `}`, fmt.Sprintf("%v", http.Header{authorizationHeaderFixture: {list}}), fmt.Sprintf("%#v", http.Header{authorizationHeaderFixture: {list}})} {
						got := maskCredentialFindings(input, scanner.Scan([]byte(input)))
						if strings.Contains(got, secret) {
							t.Fatalf("credential visible: %q => %q", input, got)
						}
					}
				}
			}
		}
	}
}

func TestDetectorDefaultCredentialSegmentsProperty(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, prefix := range []string{"SECRET", "POSTGRES", "MYSQL", "GITHUB", "AWS_SESSION", "X-Auth", "spring.datasource", "user", strings.Repeat("component.", 10)} {
		for _, word := range []string{"password", "passwd", "secret", "token", string(KindCredential), "auth"} {
			for _, separator := range []string{"_", "-", ".", ""} {
				suffix := word
				if separator == "" {
					suffix = strings.ToUpper(word[:1]) + word[1:]
				}
				key := prefix + separator + suffix
				// #nosec G101 -- Synthetic generated-key fixture, not a credential.
				secret := "opaqueSegmentFixture"
				input := key + "=" + secret
				if got := maskCredentialFindings(input, scanner.Scan([]byte(input))); strings.Contains(got, secret) {
					t.Errorf("assignment: %q => %q", input, got)
				}
				document := []byte(`{"` + key + `":"` + secret + `"}`)
				if got := maskCredentialFindings(string(document), scanner.Scan(document)); strings.Contains(got, secret) {
					t.Errorf("JSON key %q: %s", key, got)
				}
			}
		}
	}
	for _, key := range []string{"SECRET_KEY", "secretKey", "X-Goog-Api-Key", "AWS_SECRET_ACCESS_KEY"} {
		if got := maskCredentialFindings(key+"=opaqueSegmentFixture", scanner.Scan([]byte(key+"=opaqueSegmentFixture"))); strings.Contains(got, "opaqueSegmentFixture") {
			t.Errorf("key %s visible", key)
		}
	}
	for _, key := range []string{"primary_key", "sort_key", "foreign_key", "monkey", "keyboard", "token_count", "password_length", "secret_name", "authentication_status"} {
		input := key + "=ordinary"
		if got := maskCredentialFindings(input, scanner.Scan([]byte(input))); got != input {
			t.Errorf("noncredential key %s masked", key)
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
				for _, input := range []string{fmt.Sprintf(verb, map[string]any{"password": value}), fmt.Sprintf(verb, map[string]any{authorizationHeaderFixture: value}), fmt.Sprintf(verb, struct{ Password any }{value})} {
					// Plain struct %v and %q omit field names; no credential context survives.
					if !strings.Contains(strings.ToLower(input), "password") && !strings.Contains(input, authorizationHeaderFixture) {
						continue
					}
					got := maskCredentialFindings(input, scanner.Scan([]byte(input)))
					hexBytes := fmt.Sprintf("%#v", []byte(secret))
					if strings.Contains(got, secret) || strings.Contains(got, strings.TrimSuffix(strings.TrimPrefix(hexBytes, "[]byte{"), "}")) || strings.Contains(got, fmt.Sprintf("%v", []byte(secret))) {
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

func TestDetectorCredentialEscapesAndBoundariesProperty(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for n := range 16 {
		secret := fmt.Sprintf("opaqueBoundary%02dFixture", n)
		inputs := make([]string, 0, 18)
		inputs = append(inputs, "map[password:"+secret+" tail user:bob]", "{Password:head "+secret+" tail}", "password=`head "+secret+" tail`", "password := "+secret, "{DSN:{Scheme:https Opaque: User:bob:"+secret+" Host:example.com Path:/x}}")
		for _, prefix := range []string{"[]", "[abc]", ",", ")", "[REDACTED]]", "[REDACTED][REDACTED]"} {
			inputs = append(inputs, "password="+prefix+secret)
		}
		escaped := `{"password":"` + secret + `"}`
		for range 4 {
			inputs = append(inputs, escaped)
			escaped = strconv.Quote(escaped)
		}
		for _, quote := range []string{`\x22`, `\u0022`} {
			inputs = append(inputs, "{"+quote+"password"+quote+":"+quote+secret+quote+"}")
		}
		for _, input := range inputs {
			if got := maskCredentialFindings(input, scanner.Scan([]byte(input))); strings.Contains(got, secret) {
				t.Errorf("boundary visible: %q => %q", input, got)
			}
		}
	}
}

func TestDetectorCredentialYAMLBlockProperty(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, indent := range []string{"", "  ", "    "} {
		for _, indicator := range []string{"|", ">", "|-", ">+", "|2"} {
			input := indent + "password: " + indicator + "\n" + indent + "  opaqueBlockFixture\n" + indent + "  opaqueBodyFixture\n" + indent + "public: retained\n"
			got := maskCredentialFindings(input, scanner.Scan([]byte(input)))
			if strings.Contains(got, "opaque") || !strings.Contains(got, "public: retained") {
				t.Errorf("block boundary: %q => %q", input, got)
			}
		}
	}
}

func maskCredentialFindings(input string, findings []Finding) string {
	data := []byte(input)
	for _, finding := range findings {
		for at := finding.Start; at < finding.End; at++ {
			data[at] = '*'
		}
	}
	return string(data)
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
		assignmentPrefix = "password="
		scalar           = "fixture"
		publicLine       = "\npublic=kept"
		formatted        = "head fixture tail"
		publicJSON       = `","public":"kept"}`
	)

	for n := range 16 {
		secret := fmt.Sprintf("opaqueOuter%02dFixture", n)
		for _, tc := range []struct{ before, value, after string }{
			{assignmentPrefix, scalar, " public=kept"},
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
			{assignmentPrefix, "[]fixture", publicLine},
			{assignmentPrefix, "[REDACTED]]fixture", publicLine},
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
		key := strings.Repeat("service_", length) + "password"
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
