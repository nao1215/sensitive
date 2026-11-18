package embargotest

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nao1215/embargo"
)

func TestCanaryHTTPInputs(t *testing.T) {
	t.Parallel()
	r := New(t)
	// Standard library types carry the canary into HTTP inputs.
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.com/", bytes.NewReader(r.Canary()))
	request.Header.Set("Authorization", string(r.Canary()))
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, r.Canary()) || request.Header.Get("Authorization") != string(r.Canary()) {
		t.Fatal("input differs")
	}
	logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(r.Writer("logs"), nil), embargo.NewScanner()))
	logger.Info("received", slog.String("authorization", request.Header.Get("Authorization")), slog.String("token", string(body)))
	r.ExpectJSON("logs", nil, map[string]string{"authorization": injectedMarker, "token": injectedMarker}, 1)
	r.Check()
}

func TestCanaryFileInput(t *testing.T) {
	t.Parallel()
	r := New(t)
	path := r.File("password")
	// #nosec G304 -- Private temporary canary file returned by File.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, r.Canary()) {
		t.Fatal("file differs")
	}
	if _, err := r.Writer("logs").Write([]byte(embargo.NewSecret(data).String())); err != nil {
		t.Fatal(err)
	}
	r.Expect("logs", func(data []byte) bool { return len(data) > 0 })
	r.Check()
}

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

const injectedMarker = "[REDACTED]"
