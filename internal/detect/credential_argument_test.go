package detect

import "testing"

func TestCredentialQuotedArgumentsAndSubscripts(t *testing.T) {
	t.Parallel()
	d := &Credential{}
	for input, want := range map[string]string{
		`System.setProperty("db.password", "` + fixturePassword + `")`: fixturePassword,
		`props.put('javax.net.ssl.keyStorePassword' , 'changeit')`:     "changeit",
		`Map.of("user", "bob", "api_key", "k-123")`:                    "k-123",
		`{"secret", "s3"}`: "s3",
		`headers.set("Authorization", "Bearer bearer-token")`:   "bearer-token",
		`os.environ["DB_PASSWORD"] = "` + fixturePassword + `"`: fixturePassword,
		`ENV['SECRET_KEY']='s-key'`:                             "s-key",
		`f("password", "a\"b")`:                                 `a\"b`,
		`log("password", "[REDACTED]") then f("token", "t-1")`:  "t-1",
		`setProperty("password",` + "\n" + `"next-line")`:       "",
		`f("password" + "x")`:                                   "",
		`f("password", x)`:                                      "",
		`f("password", "")`:                                     "",
		`x"password", "y"`:                                      "",
		`["password", "token"]`:                                 "",
		`f("username", "bob")`:                                  "",
		`env[""] = "x"`:                                         "",
		`f("password", "unterminated`:                           "unterminated",
		`f("unterminated`:                                       "",
	} {
		got := make([]string, 0, 1)
		for _, f := range d.Scan([]byte(input)) {
			got = append(got, input[f.Start:f.End])
		}
		if want == "" && len(got) != 0 || want != "" && (len(got) != 1 || got[0] != want) {
			t.Errorf("Scan(%q) = %q, want %q", input, got, want)
		}
	}
}
