package embargo

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestLargeJSONSnapshot(t *testing.T) {
	t.Parallel()
	// Duplicate keys, exact integers and arrays stay visible
	// in the diff. Inspect their meaning before comparing stored bytes.
	source := `{"header":{"sequence":9007199254740993,"ok":true},"rows":[` + strings.TrimSuffix(strings.Repeat(`{"email":"alice@example.com","password":{"opaque":"fixture-private"},"clean":"public","dup":1,"dup":2},`, 32), ",") + `],"tail":null}`
	output, err := NewScanner(WithAll()).MaskJSON([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(output) || bytes.Contains(output, []byte("alice")) || bytes.Contains(output, []byte("fixture-private")) {
		t.Fatal("snapshot is invalid or contains synthetic secrets")
	}
	if bytes.Count(output, []byte(`"dup":1,"dup":2`)) != 32 || !bytes.Contains(output, []byte("9007199254740993")) || bytes.Count(output, []byte(`"clean":"public"`)) != 32 {
		t.Fatal("snapshot lost clean data or duplicate fields")
	}
	var formatted bytes.Buffer
	if err = json.Indent(&formatted, output, "", "  "); err != nil {
		t.Fatal(err)
	}
	if err = formatted.WriteByte('\n'); err != nil {
		t.Fatal(err)
	}
	const path = "testdata/large-json.golden"
	if os.Getenv("UPDATE_SNAPSHOTS") == "1" {
		if err = os.WriteFile(path, formatted.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, formatted.Bytes()) {
		t.Fatal("large JSON snapshot changed; review field structure")
	}
}
