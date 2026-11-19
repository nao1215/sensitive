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

// unknownKindPanic is the message for an unknown kind that is not a misspelling.
const unknownKindPanic = "embargo: unknown built-in kind"

func TestWithKindsPanicNamesOnlyMisspellings(t *testing.T) {
	t.Parallel()
	for kind, want := range map[embargo.Kind]string{
		"emial":               `embargo: unknown built-in kind "emial" (did you mean "email"?)`,
		"pa":                  `embargo: unknown built-in kind "pa" (did you mean "pan"?)`,
		"IPADDR":              unknownKindPanic,
		"opaqueFixtureValue1": unknownKindPanic,
		"zzzpan":              unknownKindPanic,
		"":                    unknownKindPanic,
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

func TestWithMoreKindsAddsToTheSelection(t *testing.T) {
	t.Parallel()
	const myNumber = "my_number=123456789018"
	const email = "alice@example.com"
	tests := []struct {
		name                    string
		opts                    []embargo.ScannerOption
		wantMyNumber, wantEmail bool
	}{
		{name: "default", opts: nil, wantMyNumber: false, wantEmail: true},
		{name: "added to the default", opts: []embargo.ScannerOption{embargo.WithMoreKinds(embargo.KindMyNumber)}, wantMyNumber: true, wantEmail: true},
		{name: "added to WithKinds", opts: []embargo.ScannerOption{embargo.WithKinds(embargo.KindPAN), embargo.WithMoreKinds(embargo.KindMyNumber)}, wantMyNumber: true, wantEmail: false},
		{name: "WithKinds afterwards replaces it", opts: []embargo.ScannerOption{embargo.WithMoreKinds(embargo.KindMyNumber), embargo.WithKinds(embargo.KindEmail)}, wantMyNumber: false, wantEmail: true},
		{name: "two calls add up", opts: []embargo.ScannerOption{embargo.WithKinds(), embargo.WithMoreKinds(embargo.KindMyNumber), embargo.WithMoreKinds(embargo.KindEmail)}, wantMyNumber: true, wantEmail: true},
		{name: "nothing added", opts: []embargo.ScannerOption{embargo.WithMoreKinds()}, wantMyNumber: false, wantEmail: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := embargo.NewScanner(tt.opts...)
			if got := len(s.ScanString(myNumber)) > 0; got != tt.wantMyNumber {
				t.Errorf("My Number found = %v, want %v", got, tt.wantMyNumber)
			}
			if got := len(s.ScanString(email)) > 0; got != tt.wantEmail {
				t.Errorf("email found = %v, want %v", got, tt.wantEmail)
			}
		})
	}
}

func TestWithMoreKindsCopiesAndRejectsUnknownKinds(t *testing.T) {
	t.Parallel()
	kinds := []embargo.Kind{embargo.KindMyNumber}
	opt := embargo.WithMoreKinds(kinds...)
	kinds[0] = embargo.KindPAN
	if s := embargo.NewScanner(opt); len(s.ScanString("my_number=123456789018")) != 1 || len(s.ScanString("card 4111111111111111")) != 1 {
		t.Fatal("WithMoreKinds did not copy its kinds")
	}
	defer func() {
		if got := recover(); got != `embargo: unknown built-in kind "mynumbr" (did you mean "mynumber"?)` {
			t.Fatalf("panic = %v", got)
		}
	}()
	embargo.WithMoreKinds("mynumbr")
}
