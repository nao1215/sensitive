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
