package tests

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	slogformatter "github.com/samber/slog-formatter"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nao1215/embargo"
	embargozap "github.com/nao1215/embargo/adapters/zap"
	"github.com/nao1215/embargo/embargotest"
)

const (
	scenarioRedirect = "redirect"
	scenarioPlain    = "plain"
	scenarioZap      = "embargo/zap"
	scenarioSlog     = "embargo/slog"
	scenarioTokenKey = "token"
	scenarioErrorKey = "error"
)

type serviceConfig struct {
	DSN      string `json:"dsn"`
	Password string `json:"password"`
}
type scenarioService struct {
	emit   func(string, ...slog.Attr)
	config serviceConfig
	token  string
}

func (s scenarioService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/declared":
		s.emit("configured", slog.String("password", s.config.Password))
	case "/config":
		s.emit("connecting", slog.Any("config", s.config))
	case "/error":
		s.emit("checkout failed", slog.Any(scenarioErrorKey, fmt.Errorf("database unavailable: %w", errors.New(s.config.DSN))))
	case "/joined":
		s.emit("checkout failed", slog.Any(scenarioErrorKey, errors.Join(errors.New(s.config.DSN), errors.New("token="+s.token))))
	case "/request":
		s.emit("upstream request Authorization: Bearer " + s.token)
	case "/token":
		s.emit("upstream rejected " + s.token)
	case "/redirect":
		http.Redirect(w, r, "/retry?token="+s.token, http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func scenarioEmit(t *testing.T, mode string, out io.Writer) func(string, ...slog.Attr) {
	t.Helper()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential, embargo.KindServiceToken))
	if mode == scenarioZap {
		config := zap.NewProductionEncoderConfig()
		config.TimeKey = ""
		logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(config), embargozap.NewWriteSyncer(zapcore.AddSync(out), scanner), zap.InfoLevel))
		return func(message string, attrs ...slog.Attr) {
			fields := make([]zap.Field, 0, len(attrs))
			for _, a := range attrs {
				fields = append(fields, zap.Any(a.Key, a.Value.Any()))
			}
			logger.Info(message, fields...)
		}
	}
	var handler slog.Handler = slog.NewJSONHandler(out, nil)
	switch mode {
	case scenarioSlog:
		handler = embargo.NewSlogHandler(handler, scanner)
	case "masq":
		handler = slog.NewJSONHandler(out, &slog.HandlerOptions{ReplaceAttr: comparisonMasq()})
	case "slog-formatter":
		handler = slogformatter.NewFormatterHandler(slogformatter.FormatByKey("password", func(slog.Value) slog.Value { return slog.StringValue("[REDACTED]") }), slogformatter.FormatByKey(scenarioTokenKey, func(slog.Value) slog.Value { return slog.StringValue("[REDACTED]") }))(handler)
	}
	logger := slog.New(handler)
	return func(message string, attrs ...slog.Attr) {
		if mode == "go-mask" {
			payload := map[string]any{}
			for _, a := range attrs {
				payload[a.Key] = a.Value.Any()
			}
			masked, err := comparisonMasker().Mask(payload)
			if err != nil {
				t.Fatal(err)
			}
			values, ok := masked.(map[string]any)
			if !ok {
				t.Fatal("mask changed container type")
			}
			attrs = nil
			for k, v := range values {
				attrs = append(attrs, slog.Any(k, v))
			}
		}
		logger.LogAttrs(t.Context(), slog.LevelInfo, message, attrs...)
	}
}

func TestLeakScenarios(t *testing.T) {
	t.Parallel()
	modes := []string{scenarioSlog, scenarioZap, "masq", "slog-formatter", "go-mask"}
	var table strings.Builder
	writeComparisonTable(t, &table, "| Service output | embargo slog | embargo zap | masq v0.2.3 | slog-formatter v1.3.0 | go-mask v0.6.2 |\n|---|---|---|---|---|---|\n")
	rows := []struct{ path, label string }{
		{"declared", "Password under the key `password`"},
		{"config", "Config struct holding a database DSN"},
		{scenarioErrorKey, "DSN inside a wrapped error"},
		{"joined", "DSN and an API key joined with errors.Join"},
		{"request", "Bearer header value in a log message"},
		{scenarioTokenKey, "Third-party API key in a log message"},
		{scenarioRedirect, "Redirect URL query, never logged"},
	}
	for _, row := range rows {
		path := row.path
		writeComparisonTable(t, &table, "| %s |", row.label)
		for _, mode := range modes {
			var logs bytes.Buffer
			password := "pretend-database-password"
			token := "sk-proj-" + strings.Repeat("Fake0", 8)
			service := scenarioService{config: serviceConfig{DSN: "postgres://reader:" + password + "@db.example/orders", Password: password}, token: token, emit: scenarioEmit(t, mode, &logs)}
			response := httptest.NewRecorder()
			service.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/"+path, nil))
			//nolint:errchkjson // Keep future serialization failures explicit.
			body, err := json.Marshal(response.Header())
			if err != nil {
				t.Fatal(err)
			}
			all := logs.String() + response.Body.String() + string(body)
			leaked := strings.Contains(all, password) || strings.Contains(all, token)
			verdict := "caught"
			if leaked {
				verdict = "leaked"
			}
			if strings.HasPrefix(mode, "embargo/") && path != scenarioRedirect && leaked {
				t.Fatalf("%s %s leaked", mode, path)
			}
			if path != scenarioRedirect && logs.Len() == 0 {
				t.Fatal("missing log is not proof of protection")
			}
			writeComparisonTable(t, &table, " %s |", verdict)
		}
		writeComparisonTable(t, &table, "\n")
	}
	syncDocTable(t, "../doc/comparison.md", "leak-scenarios", table.String())
	syncDocTable(t, "../README.md", "leak-scenarios", table.String())
}

func TestLeakScenarioGuard(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{scenarioPlain, scenarioSlog, scenarioZap} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe, embargotest.WithScanner(embargo.NewScanner(embargo.WithKinds(embargo.KindCredential, embargo.KindServiceToken))))
			// #nosec G101 -- Public fictitious DSN used to test leakage, never a live credential.
			service := scenarioService{config: serviceConfig{DSN: "postgres://reader:pretend@db.example/orders"}, token: "sk-proj-" + strings.Repeat("Fake0", 8), emit: scenarioEmit(t, mode, r.Writer("logs"))}
			service.ServeHTTP(r.HTTP("response"), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/joined", nil))
			r.Expect("logs", func(data []byte) bool { return len(data) > 0 })
			if r.Check() != (mode != scenarioPlain) {
				t.Fatal("incorrect planted leak verdict")
			}
			probe.finish()
		})
	}
}
