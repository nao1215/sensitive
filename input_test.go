package embargo

import (
	"bytes"
	"database/sql"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type (
	namedString string
	namedBytes  []byte
)

const (
	jsonNull               = "null"
	encodedRedactionOutput = `"[REDACTED]"`
	invalidInputMessage    = "embargo: invalid input"
)

func (*namedString) UnmarshalJSON([]byte) error { panic("custom decoder called") }

func (*namedBytes) UnmarshalText([]byte) error { panic("custom decoder called") }

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
	for _, raw := range []string{jsonNull, "true", "123", "{}", "[]", `"unterminated`, encodedRedactionOutput} {
		var input Input[string]
		if err := input.UnmarshalText([]byte("previous")); err != nil {
			t.Fatal(err)
		}
		err := input.UnmarshalJSON([]byte(raw))
		if err == nil || err.Error() != invalidInputMessage || input.Secret().Reveal() != "" {
			t.Fatal("failure contract changed")
		}
	}
	// A byte Input that held a value is cleared by every kind of failure.
	for _, raw := range []string{`"bad base64!"`, `"W1JFREFDVEVEXQ=="`, jsonNull, "123"} {
		var input Input[[]byte]
		if err := input.UnmarshalText([]byte("previous")); err != nil {
			t.Fatal(err)
		}
		err := input.UnmarshalJSON([]byte(raw))
		if err == nil || err.Error() != invalidInputMessage || input.Secret().Reveal() != nil {
			t.Fatalf("byte failure contract changed for %s", raw)
		}
	}
	var nilInput *Input[string]
	for _, err := range []error{nilInput.UnmarshalJSON([]byte(`"secret"`)), nilInput.UnmarshalText([]byte("secret"))} {
		if err == nil || err.Error() != invalidInputMessage {
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
			if err := dst.UnmarshalJSON(data); err == nil || err.Error() != invalidInputMessage {
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
	if v.String() != redactionMarker || v.LogValue().String() != redactionMarker || fmt.Sprintf("%+#v", v) != redactionMarker {
		t.Fatal("input display changed")
	}
	data, err := v.MarshalText()
	if err != nil || string(data) != redactionMarker {
		t.Fatal("input text changed")
	}
}

//nolint:goconst // Explicit invalid fixtures document the decoder contract.
func TestInputScanCopiesAndClears(t *testing.T) {
	t.Parallel()
	var input Input[[]byte]
	var scanner sql.Scanner = &input
	raw := []byte("database-secret")
	if err := scanner.Scan(raw); err != nil {
		t.Fatal(err)
	}
	snapshot := input.Secret()
	raw[0] = 'X'
	if string(snapshot.Reveal()) != "database-secret" {
		t.Fatal("driver buffer retained")
	}
	if err := scanner.Scan("next"); err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Reveal()) != "database-secret" {
		t.Fatal("snapshot changed")
	}
	for _, invalid := range []any{42, true, []byte("[REDACTED]"), "[REDACTED]"} {
		err := scanner.Scan(invalid)
		if err == nil || strings.Contains(err.Error(), "REDACTED") || len(input.Secret().Reveal()) != 0 {
			t.Fatal("failed scan must clear with fixed error")
		}
	}
	if err := scanner.Scan(nil); err != nil || input.Secret().Reveal() != nil {
		t.Fatal("NULL must clear")
	}
	var missing *Input[string]
	if missing.Scan("x") == nil {
		t.Fatal("nil receiver accepted")
	}
	var named Input[secretText]
	if err := named.Scan([]byte("raw")); err != nil || named.Secret().Reveal() != "raw" {
		t.Fatal("named string failed")
	}
	var text encoding.TextUnmarshaler = &named
	if err := text.UnmarshalText([]byte("config-secret")); err != nil || named.Secret().Reveal() != "config-secret" {
		t.Fatal("text input failed")
	}
}

type secretText string

func FuzzInput(f *testing.F) {
	for _, seed := range []string{`"hello"`, `null`, encodedRedactionOutput, `"W1JFREFDVEVEXQ=="`, `"bad base64!"`, "\xff"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var text Input[string]
		var binary Input[[]byte]
		errText := text.UnmarshalJSON(data)
		errBytes := binary.UnmarshalJSON(data)
		var raw *string
		err := json.Unmarshal(data, &raw)
		valid := err == nil && raw != nil && *raw != redactionMarker
		if (errText == nil) != valid {
			t.Fatal("string decoder disagrees with JSON")
		}
		if valid && text.Secret().Reveal() != *raw {
			t.Fatal("decoded string differs")
		}
		if !valid && text.Secret().Reveal() != "" {
			t.Fatal("failure retained input")
		}
		if valid {
			decoded, err := base64.StdEncoding.DecodeString(*raw)
			valid = err == nil && string(decoded) != redactionMarker
			if valid && !bytes.Equal(binary.Secret().Reveal(), decoded) {
				t.Fatal("decoded bytes differ")
			}
		}
		if (errBytes == nil) != valid {
			t.Fatal("byte decoder disagrees with base64")
		}
		if err := text.UnmarshalText(data); (err == nil) != (string(data) != redactionMarker) {
			t.Fatal("text redactionMarker boundary changed")
		}
	})
}
