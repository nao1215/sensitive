package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestSnapshotStoresOnlyLocationsAndDigests(t *testing.T) {
	t.Parallel()
	raw := "card=4111111111111111"
	got := measure(embargo.NewScanner(), "synthetic", []byte(raw))
	if len(got.Findings) != 1 || got.Findings[0].Start != 5 || got.Findings[0].End != len(raw) || got.MaskedSHA256 != digest([]byte("card=[REDACTED]")) {
		t.Fatal("wrong fixed-corpus measurement", got)
	}
	data, err := json.Marshal(got)
	if err != nil || strings.Contains(string(data), "411111") {
		t.Fatal("snapshot contains raw input")
	}
	clean := measure(embargo.NewScanner(), "clean", []byte("public"))
	if clean.Findings == nil || len(clean.Findings) != 0 || clean.InputSHA256 != clean.MaskedSHA256 {
		t.Fatal("clean baseline changed")
	}
}
