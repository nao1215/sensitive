package tests

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
	"github.com/nao1215/embargo/tests/domain"
)

func TestDomainValueContract(t *testing.T) {
	t.Parallel()
	embargotest.CheckValue(t, func(s string) any { return domain.NewPassword(s) })
	for _, jsonOutput := range []bool{false, true} {
		var out bytes.Buffer
		var next slog.Handler = slog.NewTextHandler(&out, nil)
		if jsonOutput {
			next = slog.NewJSONHandler(&out, nil)
		}
		logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner(embargo.WithKinds())))
		logger.Info("domain", slog.Any("value", domain.NewPassword("unrecognizable-opaque-value")), slog.Any("nested", struct {
			Value domain.Password `json:"value"`
		}{Value: domain.NewPassword("unrecognizable-opaque-value")}))
		if bytes.Contains(out.Bytes(), []byte("unrecognizable")) || !bytes.Contains(out.Bytes(), []byte("[REDACTED]")) {
			t.Fatal("domain output methods were bypassed")
		}
	}
}

func TestWrappedJoinedErrorText(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("request failed: %w", errors.Join(errors.New("postgres://reader:forgotten@db.example/orders"), errors.New("token=opaque-upstream-value")))
	var out bytes.Buffer
	logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))))
	logger.Error("failure", slog.Any("error", err))
	var record map[string]string
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	want := "request failed: postgres://reader:[REDACTED]@db.example/orders\ntoken=[REDACTED]"
	if record["error"] != want {
		t.Fatalf("wrong error text: %s", record["error"])
	}
}

func TestDomainValueDocumentation(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile("domain/password.go")
	if err != nil {
		t.Fatal(err)
	}
	syncDocTable(t, "../doc/values.md", "domain-value", "```go\n"+string(source)+"```\n")
}
