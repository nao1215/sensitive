package embargo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

type (
	namedString string
	namedBytes  []byte
)

func (*namedString) UnmarshalJSON([]byte) error { panic("custom decoder called") }
func (*namedBytes) UnmarshalText([]byte) error  { panic("custom decoder called") }

func TestInputSnapshot(t *testing.T) {
	t.Parallel()
	var input Input[namedBytes]
	raw := []byte("first")
	if err := input.UnmarshalText(raw); err != nil {
		t.Fatal(err)
	}
	before := input.Secret()
	raw[0] = 'x'
	if string(before.Reveal()) != "first" {
		t.Fatal("input buffer shared")
	}
	if err := input.UnmarshalJSON([]byte(`"c2Vjb25k"`)); err != nil {
		t.Fatal(err)
	}
	if string(before.Reveal()) != "first" || string(input.Secret().Reveal()) != "second" {
		t.Fatal("snapshot changed")
	}
	var text Input[namedString]
	if err := text.UnmarshalJSON([]byte(`"hello"`)); err != nil {
		t.Fatal(err)
	}
	if text.Secret().Reveal() != "hello" {
		t.Fatal("named string not decoded")
	}
}

func TestInputFailures(t *testing.T) {
	t.Parallel()
	//nolint:goconst // Keep expected marker and error strings independent of production constants.
	for _, raw := range []string{"null", "true", "123", "{}", "[]", `"unterminated`, `"[REDACTED]"`} {
		var input Input[string]
		if err := input.UnmarshalText([]byte("previous")); err != nil {
			t.Fatal(err)
		}
		err := input.UnmarshalJSON([]byte(raw))
		//nolint:goconst // Keep expected marker and error strings independent of production constants.
		if err == nil || err.Error() != "embargo: invalid input" || input.Secret().Reveal() != "" {
			t.Fatal("failure contract changed")
		}
	}
	// A byte Input that held a value is cleared by every kind of failure.
	for _, raw := range []string{`"bad base64!"`, `"W1JFREFDVEVEXQ=="`, "null", "123"} {
		var input Input[[]byte]
		if err := input.UnmarshalText([]byte("previous")); err != nil {
			t.Fatal(err)
		}
		err := input.UnmarshalJSON([]byte(raw))
		if err == nil || err.Error() != "embargo: invalid input" || input.Secret().Reveal() != nil {
			t.Fatalf("byte failure contract changed for %s", raw)
		}
	}
	var nilInput *Input[string]
	for _, err := range []error{nilInput.UnmarshalJSON([]byte(`"secret"`)), nilInput.UnmarshalText([]byte("secret"))} {
		if err == nil || err.Error() != "embargo: invalid input" {
			t.Fatal("nil receiver contract")
		}
	}
}

func TestInputMarkerRoundTrip(t *testing.T) {
	t.Parallel()
	var s Input[string]
	var b Input[[]byte]
	for _, dst := range []interface {
		UnmarshalJSON([]byte) error
		UnmarshalText([]byte) error
	}{&s, &b} {
		for _, original := range []any{NewSecret("fake secret"), NewSecret([]byte("fake secret")), s, b} {
			data, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			if err := dst.UnmarshalJSON(data); err == nil || err.Error() != "embargo: invalid input" {
				t.Fatal("redacted JSON round trip succeeded")
			}
		}
		if err := dst.UnmarshalText([]byte(redactionMarker)); err == nil {
			t.Fatal("redacted text round trip succeeded")
		}
	}
	encoded := `"` + base64.StdEncoding.EncodeToString([]byte(redactionMarker)) + `"`
	if err := b.UnmarshalJSON([]byte(encoded)); err == nil {
		t.Fatal("encoded redactionMarker accepted")
	}
	if s.Secret().Reveal() != "" || b.Secret().Reveal() != nil {
		t.Fatal("redactionMarker failure retained state")
	}
}

func TestInputDisplay(t *testing.T) {
	t.Parallel()
	var v Input[string]
	if err := v.UnmarshalText([]byte("fake-secret-value")); err != nil {
		t.Fatal(err)
	}
	if v.String() != redactionMarker || v.GoString() != redactionMarker || v.LogValue().String() != redactionMarker || fmt.Sprintf("%+#v", v) != redactionMarker {
		t.Fatal("input display changed")
	}
	data, err := v.MarshalText()
	if err != nil || string(data) != redactionMarker {
		t.Fatal("input text changed")
	}
}
