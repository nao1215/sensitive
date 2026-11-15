package embargotest

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Setenv injects the fake canary into an environment variable using testing.TB's
// Setenv, which restores it at cleanup and rejects parallel tests. Use this for
// code that loads credentials from the process environment.
func (r *Recorder) Setenv(key string) { r.tb.Helper(); r.tb.Setenv(key, string(r.canary)) }

// File writes the fake canary to a private temporary file and returns its path.
// The test owns cleanup. Name must be a single filename, never a path. Use it
// for secret-file configuration; compose larger configs with Canary instead.
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

// Header returns a new HTTP header containing the fake canary at name. It does
// not modify a request or share mutable storage with the recorder. Use it to
// exercise forwarding, logging or accidental response-header reflection.
func (r *Recorder) Header(name string) http.Header {
	header := make(http.Header)
	header.Set(name, string(r.canary))
	return header
}

// Reader returns an independent reader over the fake canary for request bodies,
// config parsers and other io.Reader inputs. Database fixtures can pass
// string(r.Canary()) as a standard SQL argument or textual row value.
func (r *Recorder) Reader() io.Reader { return bytes.NewReader(r.Canary()) }
