package embargologrus_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/nao1215/embargo"
)

// Snapshot differences show field order and formatter changes. The semantic
// assertions run even in update mode, before accepting new output bytes.
func TestLoggerSnapshot(t *testing.T) {
	t.Parallel()
	const marker = "[REDACTED]"
	const canary = "public-fake-canary-0123456789"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN, embargo.KindCVV), embargo.WithDetector(literal{value: []byte(canary)}))
	var output bytes.Buffer
	for range 2 {
		emit(t, &output, scanner, canary)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatal("event framing changed")
	}
	for _, line := range lines {
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		if event["pre"] != marker || event["card"] != marker || event["cvv"] != marker || event["nested"] == nil {
			t.Fatal("snapshot lost masking or structure")
		}
		nested, ok := event["nested"].(map[string]any)
		if !ok || nested["email"] != marker {
			t.Fatal("snapshot lost the nested object")
		}
		values, ok := nested["values"].([]any)
		if !ok || len(values) != 1 || values[0] != marker {
			t.Fatal("snapshot lost the nested array")
		}
		if bytes.Contains(line, []byte(canary)) || bytes.Contains(line, []byte("alice@example.com")) {
			t.Fatal("snapshot contains synthetic secret")
		}
	}
	const path = "testdata/logger.golden"
	if os.Getenv("UPDATE_SNAPSHOTS") == "1" {
		if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, output.Bytes()) {
		t.Fatal("logger snapshot changed; review field structure and ordering")
	}
}
