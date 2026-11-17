package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestMeasureSeparatesLinesAndBareSecrets(t *testing.T) {
	t.Parallel()
	const prefixed, keyword = "pulumi", "keyword-only"
	secret := "pul-" + strings.Repeat("0123456789", 4)
	// #nosec G101 -- Synthetic fixture values, not credentials.
	samples := []sample{
		{Rule: prefixed, Line: "token = " + secret, Secret: secret},
		{Rule: prefixed, Line: "x " + secret, Secret: secret},
		{Rule: keyword, Line: "password = opaque-value", Secret: "opaque-value"},
		{Rule: keyword, Line: "note opaque-value", Secret: "opaque-value"},
	}
	got := measure(embargo.NewScanner(), samples)
	if got.Rules != 2 || got.Lines != 4 || got.MaskedLines != 3 || got.RulesAllLines != 1 {
		t.Fatalf("line counts = %+v", got)
	}
	if got.Secrets != 2 || got.MaskedBare != 1 || got.RulesAllBare != 1 {
		t.Fatalf("bare counts = %+v", got)
	}
	if got.PerRule[0].Rule != keyword || got.PerRule[1].Rule != prefixed {
		t.Fatalf("rules are not sorted: %+v", got.PerRule)
	}
}

func TestReadSamplesRejectsSecretOutsideLine(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"rule":"r","line":"abc","secret":"xyz"}`,
		`{"rule":"","line":"abc","secret":"abc"}`,
		`not json`,
	} {
		if _, err := readSamples(strings.NewReader(input)); err == nil {
			t.Errorf("readSamples(%q) accepted an invalid sample", input)
		}
	}
}

func TestRunWritesJSONSummary(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "samples.jsonl")
	if err := os.WriteFile(path, []byte(`{"rule":"r","line":"password = opaque-value","secret":"opaque-value"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(path, &out); err != nil {
		t.Fatal(err)
	}
	var got summary
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.MaskedLines != 1 || got.BareContext != bareContext {
		t.Fatalf("run output %s: %v", out.String(), err)
	}
	if err := run("", &out); err == nil {
		t.Fatal("run accepted a missing --samples flag")
	}
}
