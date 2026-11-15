package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"text/template"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

func TestCompatibilityTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		emit func(io.Writer, embargo.Secret[string]) error
		name string
		call string
	}{
		{name: "fmt", call: "`fmt.Fprintf(w, \"%+#v\", secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error { _, err := fmt.Fprintf(w, "%+#v", s); return err }},
		{name: "slog TextHandler", call: "`With(\"token\", secret)` and a grouped attribute", emit: func(w io.Writer, s embargo.Secret[string]) error {
			slog.New(slog.NewTextHandler(w, nil)).With("token", s).WithGroup("nested").Info("event", "again", s)
			return nil
		}},
		{name: "slog JSONHandler", call: "`With(\"token\", secret)` and a grouped attribute", emit: func(w io.Writer, s embargo.Secret[string]) error {
			slog.New(slog.NewJSONHandler(w, nil)).With("token", s).WithGroup("nested").Info("event", "again", s)
			return nil
		}},
		{name: "encoding/json", call: "`json.NewEncoder(w).Encode(secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error { return json.NewEncoder(w).Encode(s) }},
		{name: "encoding/xml", call: "a struct field with an `xml` tag", emit: func(w io.Writer, s embargo.Secret[string]) error {
			return xml.NewEncoder(w).Encode(struct {
				Token   embargo.Secret[string] `xml:"token"`
				XMLName xml.Name               `xml:"record"`
			}{Token: s})
		}},
		{name: "text/template", call: "`{{.}}` with the secret as data", emit: func(w io.Writer, s embargo.Secret[string]) error {
			tpl, err := template.New("out").Parse("{{.}}")
			if err != nil {
				return err
			}
			return tpl.Execute(w, s)
		}},
		{name: "zap JSON core", call: "`zap.Any(\"token\", secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error {
			logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(w), zapcore.InfoLevel))
			logger.With(zap.Any("token", s)).Info("event")
			return logger.Sync()
		}},
		{name: "zerolog JSON", call: "`Interface(\"token\", secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error {
			logger := zerolog.New(w).With().Interface("token", s).Logger()
			logger.Info().Msg("event")
			return nil
		}},
		{name: "logrus JSON", call: "`WithField(\"token\", secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error {
			logger := logrus.New()
			logger.SetOutput(w)
			logger.SetFormatter(&logrus.JSONFormatter{})
			logger.WithField("token", s).Info("event")
			return nil
		}},
	}

	var table strings.Builder
	writeTable := func(text string) {
		if _, err := table.WriteString(text); err != nil {
			t.Fatal(err)
		}
	}
	writeTable("| Output | How the test writes the secret | Checked result |\n|---|---|---|\n")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := embargotest.New(t)
			r.Expect("out", func(data []byte) bool { return bytes.Contains(data, []byte("[REDACTED]")) })
			if err := tc.emit(r.Writer("out"), embargo.NewSecret(string(r.Canary()))); err != nil {
				t.Fatal("output failed")
			}
			r.Check()
		})
		writeTable("| " + tc.name + " | " + tc.call + " | `[REDACTED]` written, canary absent |\n")
	}
	for _, tc := range []struct {
		check  func(*testing.T)
		name   string
		call   string
		result string
	}{
		{name: "OTel SDK", call: "an exported span event and raw RecordError", result: "expected attributes exported; raw canary and missing flush fail", check: checkOTelAcceptance},
		{name: "Sentry", call: "Secret in scope context, CaptureException and Recover", result: "redacted event sent; raw canary and missing flush fail", check: checkSentryAcceptance},
		{name: "HTTP", call: "a real handler writing status, headers, body and trailers", result: "expected response and marker; canary absent", check: checkHTTPOutput},
		{name: "Child panic", call: "panic(secret) in a real test subprocess", result: "panic marker and stack on stderr; canary absent", check: checkChildOutput},
	} {
		t.Run(tc.name, func(t *testing.T) { t.Parallel(); tc.check(t) })
		writeTable("| " + tc.name + " | " + tc.call + " | " + tc.result + " |\n")
	}
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	const start = "<!-- tested-outputs:start -->\n"
	const end = "<!-- tested-outputs:end -->"
	before, rest, ok := strings.Cut(string(readme), start)
	if !ok {
		t.Fatal("tested outputs start marker missing")
	}
	got, after, ok := strings.Cut(rest, end)
	if !ok {
		t.Fatal("tested outputs end marker missing")
	}
	if os.Getenv("UPDATE_DOCS") == "1" {
		// #nosec G703 -- the destination is a fixed repository README, never derived from the generated table.
		if err := os.WriteFile("../README.md", []byte(before+start+table.String()+end+after), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if got != table.String() {
		t.Fatal("run make compatibility-doc: README table differs from exercised outputs")
	}
}

//nolint:goconst // Keep the expected outputs and failure modes together in this acceptance matrix.
func checkHTTPOutput(t *testing.T) {
	t.Helper()
	r := embargotest.New(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Token", embargo.NewSecret(r.Canary()).String())
		w.Header().Set("Trailer", "X-Result")
		w.WriteHeader(http.StatusAccepted)
		if _, err := fmt.Fprint(w, embargo.NewSecret(r.Canary())); err != nil {
			t.Error(err)
		}
		w.Header().Set("X-Result", "accepted")
	})
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.invalid", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(r.HTTP("http"), request)
	r.Expect("http/status", func(data []byte) bool { return string(data) == "202" })
	r.Expect("http/body", func(data []byte) bool { return string(data) == "[REDACTED]" })
	r.Expect("http/headers", func(data []byte) bool { return bytes.Contains(data, []byte("[REDACTED]")) })
	r.Expect("http/trailers", func(data []byte) bool { return bytes.Contains(data, []byte("accepted")) })
	r.Check()
}

func checkChildOutput(t *testing.T) {
	t.Helper()
	r := embargotest.New(t)
	r.Expect("stderr", func(data []byte) bool {
		return bytes.Contains(data, []byte("panic: [REDACTED]")) && bytes.Contains(data, []byte("goroutine "))
	})
	if err := r.Run(context.Background(), "TestLifecyclePanic", 2); err != nil {
		t.Fatal(err)
	}
	r.Check()
}
