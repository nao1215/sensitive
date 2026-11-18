package embargotest

import (
	"os"
	"path/filepath"
	"strings"
)

// File writes the fake canary to a private temporary file and returns its path.
// The test owns cleanup. Name must be a single filename, never a path. Use it
// for secret-file configuration; compose larger configs with Canary instead.
// Other inputs take Canary directly: t.Setenv(key, string(r.Canary())),
// bytes.NewReader(r.Canary()) or header.Set(name, string(r.Canary())).
// Failures report fixed errors and return an empty path.
func (r *Recorder) File(name string) string {
	r.tb.Helper()
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		r.tb.Error("embargotest: invalid canary filename")
		return ""
	}
	path := filepath.Join(r.tb.TempDir(), name)
	const privateFileMode = 0o600
	if err := os.WriteFile(path, r.canary, privateFileMode); err != nil {
		r.tb.Error("embargotest: canary file creation failed")
		return ""
	}
	return path
}
