package embargo_test

import (
	"database/sql"
	"encoding"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

//nolint:goconst // Explicit invalid fixtures document the decoder contract.
func TestInputScanCopiesAndClears(t *testing.T) {
	t.Parallel()
	var input embargo.Input[[]byte]
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
	var missing *embargo.Input[string]
	if missing.Scan("x") == nil {
		t.Fatal("nil receiver accepted")
	}
	var named embargo.Input[secretText]
	if err := named.Scan([]byte("raw")); err != nil || named.Secret().Reveal() != "raw" {
		t.Fatal("named string failed")
	}
	var text encoding.TextUnmarshaler = &named
	if err := text.UnmarshalText([]byte("config-secret")); err != nil || named.Secret().Reveal() != "config-secret" {
		t.Fatal("text input failed")
	}
}

type secretText string
