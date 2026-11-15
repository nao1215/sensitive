package detect

import (
	"strings"
	"testing"
)

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

func TestLogContextPreservesStandaloneValues(t *testing.T) {
	t.Parallel()
	for _, text := range []string{`token=Example@zz`, `token="Example@a"`, `token=Example@12345678901234567`, `token=example@a`, `token=Foo!@a`, `token=@a`, `token=Example@`} {
		if len((&Credential{}).Scan([]byte(text))) != 1 {
			t.Errorf("string token lost: %s", text)
		}
	}
	for _, text := range []string{"111111111118", "111111111118-note", "111111111118-", "111111111118;"} {
		if len(NewMyNumber().Scan([]byte(text))) != 1 {
			t.Errorf("standalone number lost: %s", text)
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

func TestSendGridInvalidBody(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		"SG." + strings.Repeat("a", 21) + "!." + strings.Repeat("b", 43),
		"SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 42) + "!",
	} {
		if got := (&ServiceToken{}).Scan([]byte(text)); len(got) != 0 {
			t.Fatal("punctuation accepted as a SendGrid credential byte")
		}
	}
}
