package detect

import "testing"

func TestXMLElementCredentials(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, tc := range []struct{ text, want string }{
		{`<auth><password>opaque12</password></auth>`, `<auth><password>********</password></auth>`},
		{"<apiToken>\n    opaque12\n</apiToken>", "<apiToken>\n    ********\n</apiToken>"},
		{`<wsse:Password Type="PasswordText">opaque12</wsse:Password>`, `<wsse:Password Type="PasswordText">********</wsse:Password>`},
		{`<client_secret>opaque12</client_secret><user>alice</user>`, `<client_secret>********</client_secret><user>alice</user>`},
	} {
		if got := maskCredentialFindings(tc.text, scanner.Scan([]byte(tc.text))); got != tc.want {
			t.Errorf("Scan(%q) masked to %q, want %q", tc.text, got, tc.want)
		}
	}
}

func TestXMLElementCredentialsKeepNonValues(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, text := range []string{
		`<password></password>`,
		`<password/>`,
		`<password>[REDACTED]</password>`,
		`<password><hash>abc</hash></password>`,
		`<password>opaque12</secret>`,
		`<username>alice</username>`,
		`<1password>opaque12</1password>`,
		`a < password > b`,
		`<password>opaque12`,
	} {
		if got := scanner.Scan([]byte(text)); len(got) != 0 {
			t.Errorf("Scan(%q) = %+v, want none", text, got)
		}
	}
}
