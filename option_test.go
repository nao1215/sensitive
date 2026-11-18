package embargo_test

import (
	"testing"

	"github.com/nao1215/embargo"
)

func TestOptionsCopyAndOrder(t *testing.T) {
	t.Parallel()
	kinds := []embargo.Kind{embargo.KindEmail}
	opt := embargo.WithKinds(kinds...)
	kinds[0] = embargo.KindPAN
	s := embargo.NewScanner(nil, opt, embargo.WithMinConfidence(.9))
	if len(s.ScanString("alice@example.com")) != 1 || len(s.ScanString("4111111111111111")) != 0 {
		t.Fatal("option did not copy selection")
	}
	if len(embargo.NewScanner(opt, embargo.WithAll()).ScanString("192.0.2.1")) == 0 {
		t.Fatal("WithAll did not reset selection")
	}
	if len(embargo.NewScanner(embargo.WithKinds(embargo.KindBankAccount), embargo.WithMinConfidence(.9)).ScanString("bank account 12345678")) != 0 {
		t.Fatal("threshold ignored")
	}
}

func TestWithKindsPanicNamesOnlyMisspellings(t *testing.T) {
	t.Parallel()
	for kind, want := range map[embargo.Kind]string{
		"emial":               `embargo: unknown built-in kind "emial" (did you mean "email"?)`,
		"pa":                  `embargo: unknown built-in kind "pa" (did you mean "pan"?)`,
		"IPADDR":              "embargo: unknown built-in kind",
		"opaqueFixtureValue1": "embargo: unknown built-in kind",
		"":                    "embargo: unknown built-in kind",
	} {
		func() {
			defer func() {
				if got := recover(); got != want {
					t.Errorf("WithKinds(%q) panic = %v, want %q", kind, got, want)
				}
			}()
			embargo.WithKinds(kind)
		}()
	}
}
