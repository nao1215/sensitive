package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repositoryKinds(t *testing.T) []kindDoc {
	t.Helper()
	kinds, err := readKinds("../../../finding.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 37 {
		t.Fatalf("got %d kinds, want 37", len(kinds))
	}
	return kinds
}

func repositoryReadme(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func TestKindGodocValidation(t *testing.T) {
	t.Parallel()
	for _, kind := range repositoryKinds(t) {
		t.Run(kind.name, func(t *testing.T) {
			t.Parallel()
			if _, _, _, err := columns(kind); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadmeKinds(t *testing.T) {
	t.Parallel()
	block, err := detectorBlock(repositoryReadme(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range repositoryKinds(t) {
		if strings.Count(block, "["+kind.name+"]") != 1 {
			t.Errorf("%s must have exactly one README row", kind.name)
		}
	}
	if got := strings.Count(block, "\n| [Kind"); got != len(repositoryKinds(t)) {
		t.Fatalf("unexpected README kind rows: %d", got)
	}
}

func TestReadmeFreshness(t *testing.T) {
	t.Parallel()
	if err := update("../../..", true); err != nil {
		t.Fatal(err)
	}
}

func TestKindGodocRejectsMissingValidation(t *testing.T) {
	t.Parallel()
	for _, doc := range []string{"", "KindFake selects values.", "KindFake matches digits; reports candidates (NewScanner default: on)."} {
		if _, _, _, err := columns(kindDoc{name: "KindFake", doc: doc}); err == nil {
			t.Errorf("accepted incomplete contract %q", doc)
		}
	}
}

func TestReadmeCheckRejectsStaleBlock(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source, err := os.ReadFile("../../../finding.go")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G703 -- The path is confined to this test temporary directory.
	if err = os.WriteFile(filepath.Join(root, "finding.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "README.md"), []byte(startMarker+"\nstale\n"+endMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = update(root, false); err != nil {
		t.Fatal(err)
	}
	if err = update(root, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "README.md")
	// #nosec G304 -- Read only the temporary README created above.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "| on |", "| off |", 1))
	// #nosec G703 -- The path is confined to this test temporary directory.
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = update(root, true); err == nil {
		t.Fatal("accepted stale README default")
	}
}
