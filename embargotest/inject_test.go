package embargotest_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

//nolint:goconst // Each output expectation states the public marker explicitly.
func TestCanaryHTTPInputs(t *testing.T) {
	t.Parallel()
	r := embargotest.New(t)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.com/", r.Reader())
	request.Header = r.Header("Authorization")
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
	r.ExpectJSON("logs", nil, map[string]string{"authorization": "[REDACTED]", "token": "[REDACTED]"}, 1)
	r.Check()
}

func TestCanaryFileInput(t *testing.T) {
	t.Parallel()
	r := embargotest.New(t)
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
