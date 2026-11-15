package embargotest

import (
	"path/filepath"
	"testing"
)

type missingFixtureDirectory struct {
	*probeTB

	directory string
}

func (p *missingFixtureDirectory) TempDir() string { return p.directory }

func TestCanaryFileRejectsPaths(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", ".", "..", "../password", "dir/password", `dir\password`} {
		p := &probeTB{TB: t}
		recorder := New(p)
		if path := recorder.File(name); path != "" || p.errors != 1 || p.messages[0] != "embargotest: invalid canary filename" {
			t.Fatalf("invalid name accepted or diagnostic exposed input: %q", name)
		}
	}
}

func TestCanaryFileCreationFailure(t *testing.T) {
	t.Parallel()
	p := &missingFixtureDirectory{probeTB: &probeTB{TB: t}, directory: filepath.Join(t.TempDir(), "missing")}
	recorder := New(p)
	if path := recorder.File("password"); path != "" || p.errors != 1 || p.messages[0] != "embargotest: canary file creation failed" {
		t.Fatal("failed fixture write did not return a fixed diagnostic and empty path")
	}
}
