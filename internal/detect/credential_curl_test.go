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
		{`curl -u "user:opa\"que" https://example.com`, `curl -u "user:********" https://example.com`},
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

func TestCurlUserPasswordsAtInputEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ text, want string }{
		{"curl -u ab:cd", "curl -u ab:**"},
		{"curl -u ab:cd:ef https://example.com", "curl -u ab:***** https://example.com"},
		{"curl -u \\\n  ab:cd", "curl -u \\\n  ab:**"},
		{`curl -u 'ab:c\' x`, `curl -u 'ab:**' x`},
		{`curl -u "ab:cd`, `curl -u "ab:**`},
		{"run curl -u ab:cd\ncurl -u ef:gh", "run curl -u ab:**\ncurl -u ef:**"},
	} {
		got := maskCredentialFindings(tc.text, curlUserPasswords([]byte(tc.text)))
		if got != tc.want {
			t.Errorf("curlUserPasswords(%q) masked to %q, want %q", tc.text, got, tc.want)
		}
	}
	for _, text := range []string{"curl", "x curl", "curl -u", "curl --user=", "curl -u   ", "curl -u \\", `curl -u "":""`, "curlx -u ab:cd", "xcurl -u ab:cd"} {
		if got := curlUserPasswords([]byte(text)); len(got) != 0 {
			t.Errorf("curlUserPasswords(%q) = %+v, want none", text, got)
		}
	}
}

// fixturePassword is a synthetic command-line password.
const fixturePassword = "hunter2"

func TestCommandLinePasswords(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ input, want string }{
		{"--password hunter2", fixturePassword},
		{"run --db-password 'hunter2' --verbose", fixturePassword},
		{"login --token\topaque-value", "opaque-value"},
		{"mysql -u root -phunter2 shop", fixturePassword},
		{"mysqldump -h db -p'hunter2' shop", fixturePassword},
		{"mariadb-dump -phunter2", fixturePassword},
		{"sshpass -p hunter2 ssh host", fixturePassword},
		{"--password", ""},
		{"--password --verbose", ""},
		{"--no-password true", ""},
		{"--password-file /etc/secret", ""},
		{"a--token opaque", ""},
		{"--token\nnext", ""},
		{"---- PASS ----", ""},
		{"mysql -u root -p", ""},
		{"mysql -u root -p shop", ""},
		{"mysql -P3306 shop", ""},
		{"mysql_host -prod", ""},
		{"mkdir -p /tmp/x", ""},
		{"sshpass -fpasswd ssh host", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := ""
			for _, f := range (&Credential{}).Scan([]byte(tc.input)) {
				got = tc.input[f.Start:f.End]
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
