package embargo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func FuzzInput(f *testing.F) {
	//nolint:goconst // Keep expected marker and error strings independent of production constants.
	for _, seed := range []string{`"hello"`, `null`, `"[REDACTED]"`, `"W1JFREFDVEVEXQ=="`, `"bad base64!"`, "\xff"} {
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
