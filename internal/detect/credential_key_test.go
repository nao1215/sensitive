package detect

import (
	"strings"
	"testing"
)

func TestCredentialLongUnknownKey(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("field", 8) + "=opaque-value password=actual-test-password"
	got := (&Credential{}).Scan([]byte(text))
	if len(got) != 1 || text[got[0].Start:got[0].End] != "actual-test-password" {
		t.Fatal("unknown long key masked or following password lost")
	}
}

func TestDetectorDefaultCredentialSegmentsProperty(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, prefix := range []string{"SECRET", "POSTGRES", "MYSQL", "GITHUB", "AWS_SESSION", "X-Auth", "spring.datasource", "user", strings.Repeat("component.", 10)} {
		for _, word := range []string{passwordKeyFixture, "passwd", "secret", "token", string(NameCredential), "auth"} {
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

func TestCredentialKeyAndPublicContext(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"api key", "API KEY", "api-key", "api.key", passwordKeyFixture, "clientSecret", "service.Auth", "accessKey", "accountKey", "privateKey"} {
		for _, separator := range []string{"=", " = ", "\t=\t", ":", ": "} {
			input := key + separator + "opaqueContractFixture public=kept"
			want := key + separator + strings.Repeat("*", len("opaqueContractFixture")) + " public=kept"
			if got := maskCredentialFindings(input, (&Credential{}).Scan([]byte(input))); got != want {
				t.Fatalf("key boundary: %q => %q", input, got)
			}
		}
	}
	for _, input := range []string{"", "=", ":", "token=Token{a64f992 ActivityRecord{de9231d}", "Bad activity token: android.os.BinderProxy@2bd79ce", credentialAssignmentFixture, "password= ", "Authorization: Bearer ", "password=\"[REDACTED]\"", "Authorization: Token [REDACTED]", "postgres://token:[REDACTED]@host/path", "User:name:public", " x User:name:public Other:kept", " User:name: Host:kept", " User:name Host:kept", " User:name:public\n Host:kept", "\"Bearer \"", "\"Basic [REDACTED]\"", "\"ordinary prose\""} {
		if got := (&Credential{}).Scan([]byte(input)); len(got) != 0 {
			t.Fatalf("public context became credential: %q: %+v", input, got)
		}
	}
	scanner := &Credential{MatchKey: func(key string) bool { return key == "recovery_code" }}
	input := "recovery_code=fixture password=public-label"
	findings := scanner.Scan([]byte(input))
	if len(findings) != 1 || input[findings[0].Start:findings[0].End] != "fixture" {
		t.Fatalf("custom key policy: %+v", findings)
	}
}

func TestCredentialCamelAcronymBoundaries(t *testing.T) {
	t.Parallel()
	keys := make([]string, 0, 17)
	for _, prefix := range []string{"a", "z"} {
		for _, word := range []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL", "AUTH"} {
			keys = append(keys, prefix+word)
		}
	}
	keys = append(keys, "CLIENTApiKey", "APIPrivateKey", "PROJECTSecretKey", "APIAccountKey", "tenantAccessKey")
	for _, key := range keys {
		input := key + "=opaqueAcronymFixture"
		got := (&Credential{}).Scan([]byte(input))
		if !SensitiveCredentialKey(key) || len(got) != 1 || got[0].Start != len(key)+1 || input[got[0].Start:got[0].End] != "opaqueAcronymFixture" {
			t.Fatalf("credential acronym boundary %q: %+v", key, got)
		}
	}
	for _, key := range []string{"APASSWORD", "ZPASSWORD", "0PASSWORD", "9PASSWORD", "aKEY", "zpassword", "akey", "clientPublicKey", "clientPrimaryKey", "clientSortKey"} {
		if got := (&Credential{}).Scan([]byte(key + "=public")); SensitiveCredentialKey(key) || len(got) != 0 {
			t.Fatalf("ordinary key became credential: %s %+v", key, got)
		}
	}
}

func TestCredentialNumberedKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"api_token_2", true},
		{"password1", true},
		{"DB_PASSWORD_02", true},
		{"some_api_token_123", true},
		{"sha256", false},
		{"oauth2", false},
		{"token_count_2", false},
		{"123", false},
	} {
		if got := credentialSuffix(tc.key); got != tc.want {
			t.Errorf("credentialSuffix(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestCredentialPluralAndJoinedKeySegments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"credentials", true},
		{"aws_credentials", true},
		{"creds", true},
		{"SUMOLOGIC_ACCESSKEY", true},
		{"stripeSecretKey", true},
		{"service_apikey", true},
		{"monkeys", false},
		{"descriptions", false},
		{"turkey", false},
	} {
		if got := credentialSuffix(tc.key); got != tc.want {
			t.Errorf("credentialSuffix(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestCredentialShortPasswordAndSessionKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		key              string
		structured, text bool
	}{
		{"pass", true, false},
		{"PWD", true, false},
		{"DB_PASS", true, true},
		{"db_pwd", true, true},
		{"--- PASS", true, false},
		{"bypass", false, false},
		{"compass", false, false},
		{"otp", true, true},
		{"sms_otp", true, true},
		{"pin", true, true},
		{"passcode", true, true},
		{"ssh_passphrase", true, true},
		{"session", true, true},
		{"JSESSIONID", true, true},
		{"PHPSESSID", true, true},
		{"session_count", false, false},
		{"spin", false, false},
	} {
		t.Run(tc.key, func(t *testing.T) {
			t.Parallel()
			if got := SensitiveCredentialKey(tc.key); got != tc.structured {
				t.Fatalf("structured key %q = %v, want %v", tc.key, got, tc.structured)
			}
			input := tc.key + "=opaqueFixture1"
			if got := (&Credential{}).Scan([]byte(input)); (len(got) == 1 && input[got[0].Start:got[0].End] == "opaqueFixture1") != tc.text {
				t.Fatalf("text key %q findings %+v, want %v", tc.key, got, tc.text)
			}
		})
	}
}

func TestCredentialNumericSessionIDsStayVisible(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"Processed session termination for sessionid: 0x14edfaa86f60027": "",
		"session=12345":           "",
		"sessionid=abcDEF123xyz":  "abcDEF123xyz",
		"session_id=0xZZ":         "0xZZ",
		"JSESSIONID=9876543210":   "9876543210",
		"session_token=123456789": "123456789",
	} {
		got := ""
		for _, f := range (&Credential{}).Scan([]byte(input)) {
			got = input[f.Start:f.End]
		}
		if got != want {
			t.Errorf("Scan(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCredentialEmptyHexSessionIsASecret(t *testing.T) {
	t.Parallel()
	if got := (&Credential{}).Scan([]byte("session=0x")); len(got) != 1 {
		t.Fatalf("Scan(session=0x) = %+v, want one finding", got)
	}
}

func TestCredentialQualifiedAuthKeys(t *testing.T) {
	t.Parallel()
	for key, want := range map[string]bool{"X-Auth-Key": true, "auth_key": true, "master_key": true, "MasterKey": true, "cache_key": false, "primary_key": false} {
		if got := SensitiveCredentialKey(key); got != want {
			t.Errorf("SensitiveCredentialKey(%q) = %v, want %v", key, got, want)
		}
	}
}
