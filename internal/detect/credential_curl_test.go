package detect

import "testing"

func TestCurlUserPasswords(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ text, want string }{
		{`curl --cacert ca.crt -u elastic:opaque$1 https://localhost:9200`, `curl --cacert ca.crt -u elastic:******** https://localhost:9200`},
		{"curl -X POST https://example.com \\\n  -u developer:opaque12", "curl -X POST https://example.com \\\n  -u developer:********"},
		{`curl --user  'johns:opaque12' https://example.com`, `curl --user  'johns:********' https://example.com`},
		{`curl --user="j.smith:opaque12" https://example.com`, `curl --user="j.smith:********" https://example.com`},
		{`curl -u ":opaque12" https://example.com`, `curl -u ":********" https://example.com`},
		{`curl -u "opaque12:" https://example.com`, `curl -u "********:" https://example.com`},
		{`curl -u "{user}":"{opaque1}" https://example.com`, `curl -u "{user}":"*********" https://example.com`},
	} {
		got := maskCredentialFindings(tc.text, curlUserPasswords([]byte(tc.text)))
		if got != tc.want {
			t.Errorf("curlUserPasswords(%q) masked to %q, want %q", tc.text, got, tc.want)
		}
	}
}

func TestCurlUserPasswordsIgnoresOtherCommands(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		`docker run -u 1000:1000 image`,
		`curl -u user https://example.com`,
		"curl https://example.com\nssh -u admin:visible",
		`mycurl -u user:visible`,
		`curl -usera:visible`,
		`curl --username admin:visible`,
	} {
		if got := curlUserPasswords([]byte(text)); len(got) != 0 {
			t.Errorf("curlUserPasswords(%q) = %+v, want none", text, got)
		}
	}
}
