package embargo_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestSecretDebugType(t *testing.T) {
	t.Parallel()
	password := embargo.NewSecret("fake-payment-password")
	for _, format := range []string{"%#v", "%+#v", "%#40.3v"} {
		if got := fmt.Sprintf(format, password); got != "embargo.Secret[string]([REDACTED])" {
			t.Fatalf("%s: %s", format, got)
		}
	}
	if got := password.GoString(); got != "embargo.Secret[string]([REDACTED])" {
		t.Fatal(got)
	}
	var zero embargo.Secret[[]byte]
	if got := fmt.Sprintf("%#v", zero); got != "embargo.Secret[[]uint8]([REDACTED])" {
		t.Fatal(got)
	}
}

type stringOnlyPassword string

//nolint:goconst // The literal is an independent output oracle.
func (stringOnlyPassword) String() string { return "[REDACTED]" }

func TestUnexportedFieldFormatting(t *testing.T) {
	t.Parallel()
	const raw = "fake-payment-password"
	homemade := struct{ password stringOnlyPassword }{password: raw}
	protected := struct{ password embargo.Secret[string] }{password: embargo.NewSecret(raw)}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(format, protected), raw) {
			t.Fatal("Secret exposed its referent")
		}
	}
	if !strings.Contains(fmt.Sprintf("%v", homemade), raw) {
		t.Fatal("fixture no longer demonstrates fmt bypassing String")
	}
}

type failedFormatState struct{}

func (failedFormatState) Write([]byte) (int, error) { return 0, errors.New("closed formatter") }
func (failedFormatState) Width() (int, bool)        { return 0, false }
func (failedFormatState) Precision() (int, bool)    { return 0, false }
func (failedFormatState) Flag(int) bool             { return true }

func TestSecretDoesNotFallBackWhenFormatterFails(t *testing.T) {
	t.Parallel()
	secret := embargo.NewSecret("fake-payment-password")
	secret.Format(failedFormatState{}, 'v')
	if secret.Reveal() != "fake-payment-password" {
		t.Fatal("formatter mutated secret")
	}
}
