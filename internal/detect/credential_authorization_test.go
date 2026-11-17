package detect

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestProxyAuthorizationCredentials(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"Proxy-Authorization", "proxy_authorization", "PROXYAUTHORIZATION"} {
		input := key + ": Basic dXNlcjpodW50ZXIy"
		got := (&Credential{}).Scan([]byte(input))
		if len(got) != 1 || input[got[0].Start:got[0].End] != "dXNlcjpodW50ZXIy" || !SensitiveCredentialKey(key) {
			t.Fatalf("credentials not masked: %v", got)
		}
	}
}

func TestDetectorAuthorizationSchemeProperty(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for n := range 24 {
		secret := fmt.Sprintf("opaqueAuth%02dFixture", n)
		for _, scheme := range []string{tokenSchemeFixture, "Negotiate", "Digest", "AWS4-HMAC-SHA256", bearerSchemeFixture, basicSchemeFixture, "'", "'Quoted'", "`", "`Wrapped`", "'Leading", "`Leading", fmt.Sprintf("Scheme%d!#$%%&'*+-.^_`|~", n)} {
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
					baseList := strings.TrimSuffix(strings.Repeat(value+", ", count), ", ")
					for _, prefix := range []string{"", "Token [REDACTED], "} {
						list := prefix + baseList
						checkAuthorizationInputs(t, scanner, secret, []string{"Authorization: " + list, "Proxy-Authorization: " + list, `{"msg":` + strconv.Quote("Authorization: "+list) + `}`, fmt.Sprintf("%v", http.Header{authorizationHeaderFixture: {list}}), fmt.Sprintf("%#v", http.Header{authorizationHeaderFixture: {list}})})
					}
				}
			}
		}
	}
}

func TestQuotedAuthorizationExactSpans(t *testing.T) {
	t.Parallel()
	for _, scheme := range []string{bearerSchemeFixture, "bEaReR", basicSchemeFixture, "basic"} {
		for _, space := range []string{" ", "   "} {
			for _, quote := range []string{"\"", "'"} {
				for _, secret := range []string{"x", "opaqueHeaderFixture"} {
					before := "header=" + quote + scheme + space
					input := before + secret + quote + " public=kept"
					got := (&Credential{}).Scan([]byte(input))
					if len(got) != 1 || got[0].Start != len(before) || got[0].End != len(before)+len(secret) || input[got[0].Start:got[0].End] != secret {
						t.Fatalf("quoted authorization boundary: %q: %+v", input, got)
					}
				}
			}
		}
	}
}

func TestAuthorizationQuotedValueSpans(t *testing.T) {
	t.Parallel()
	for _, quote := range []string{"\"", "'", "`"} {
		for _, scheme := range []string{bearerSchemeFixture, tokenSchemeFixture} {
			for _, value := range []string{"opaqueQuotedFixture", "firstFixture, Basic secondFixture"} {
				before := "Authorization: " + quote + scheme + " "
				input := before + value + quote + " public=kept"
				got := (&Credential{}).Scan([]byte(input))
				if len(got) != 1 || got[0].Start != len(before) || got[0].End != len(before)+len(value) || input[got[0].Start:got[0].End] != value {
					t.Fatalf("quoted authorization consumed public suffix: %q: %+v", input, got)
				}
			}
		}
	}
}

func TestAuthorizationMixedSchemeLists(t *testing.T) {
	t.Parallel()
	for _, first := range []string{tokenSchemeFixture, bearerSchemeFixture, "Negotiate"} {
		for _, next := range []string{"'", "'Quoted'", "`", "`Wrapped`", basicSchemeFixture} {
			for _, separator := range []string{",", ", ", ",\t", ",  \t"} {
				for _, initial := range []string{firstCredentialFixture, credentialMarker} {
					before := "Authorization: " + first + " "
					value := initial + separator + next + " secondFixture"
					input := before + value
					got := (&Credential{}).Scan([]byte(input))
					if len(got) != 1 || got[0].Start != len(before) || got[0].End != len(input) || input[got[0].Start:got[0].End] != value {
						t.Fatalf("mixed authorization list: %q: %+v", input, got)
					}
				}
			}
		}
	}
}

func TestAuthorizationSchemeByteAlphabet(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		want := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~", rune(b))
		if authSchemeByte(b) != want {
			t.Fatal(n)
		}
	}
}

func checkAuthorizationInputs(t *testing.T, scanner *Credential, secret string, inputs []string) {
	t.Helper()
	for _, input := range inputs {
		findings := scanner.Scan([]byte(input))
		checkCredentialByteCoverage(t, input, secret, findings)
		got := maskCredentialFindings(input, findings)
		if strings.Contains(got, secret) {
			t.Fatalf("credential visible: %q => %q", input, got)
		}
	}
}
