package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"strconv"
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

//nolint:goconst // The table shows and verifies literal output bytes for each logger.
func TestCompatibilityTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		emit   func(io.Writer, embargo.Secret[string]) error
		name   string
		call   string
		output string
	}{
		{name: "fmt", output: "[REDACTED]", call: "`fmt.Fprintf(w, \"%+#v\", secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error { _, err := fmt.Fprintf(w, "%+#v", s); return err }},
		{name: "slog TextHandler", output: "level=INFO msg=event token=[REDACTED] nested.again=[REDACTED]", call: "`With(\"token\", secret)` and a grouped attribute", emit: func(w io.Writer, s embargo.Secret[string]) error {
			slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{ReplaceAttr: omitTime})).With("token", s).WithGroup("nested").Info("event", "again", s)
			return nil
		}},
		{name: "slog JSONHandler", output: "{\"level\":\"INFO\",\"msg\":\"event\",\"token\":\"[REDACTED]\",\"nested\":{\"again\":\"[REDACTED]\"}}", call: "`With(\"token\", secret)` and a grouped attribute", emit: func(w io.Writer, s embargo.Secret[string]) error {
			slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: omitTime})).With("token", s).WithGroup("nested").Info("event", "again", s)
			return nil
		}},
		{name: "encoding/json", output: "\"[REDACTED]\"", call: "`json.NewEncoder(w).Encode(secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error { return json.NewEncoder(w).Encode(s) }},
		{name: "encoding/xml", output: "<record><token>[REDACTED]</token></record>", call: "a struct field with an `xml` tag", emit: func(w io.Writer, s embargo.Secret[string]) error {
			return xml.NewEncoder(w).Encode(struct {
				Token   embargo.Secret[string] `xml:"token"`
				XMLName xml.Name               `xml:"record"`
			}{Token: s})
		}},
		{name: "text/template", output: "[REDACTED]", call: "`{{.}}` with the secret as data", emit: func(w io.Writer, s embargo.Secret[string]) error {
			tpl, err := template.New("out").Parse("{{.}}")
			if err != nil {
				return err
			}
			return tpl.Execute(w, s)
		}},
		{name: "zap JSON core", output: "{\"level\":\"info\",\"msg\":\"event\",\"token\":\"[REDACTED]\"}", call: "`zap.Any(\"token\", secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error {
			config := zap.NewProductionEncoderConfig()
			config.TimeKey = ""
			logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(config), zapcore.AddSync(w), zapcore.InfoLevel))
			logger.With(zap.Any("token", s)).Info("event")
			return logger.Sync()
		}},
		{name: "zerolog JSON", output: "{\"level\":\"info\",\"token\":\"[REDACTED]\",\"message\":\"event\"}", call: "`Interface(\"token\", secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error {
			logger := zerolog.New(w).With().Interface("token", s).Logger()
			logger.Info().Msg("event")
			return nil
		}},
		{name: "logrus JSON", output: "{\"level\":\"info\",\"msg\":\"event\",\"token\":\"[REDACTED]\"}", call: "`WithField(\"token\", secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error {
			logger := logrus.New()
			logger.SetOutput(w)
			logger.SetFormatter(&logrus.JSONFormatter{DisableTimestamp: true})
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
	writeTable("| Output | Actual output (excerpt for SDKs) |\n|---|---|\n")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := embargotest.New(t)
			r.Expect("out", func(data []byte) bool { return strings.TrimSpace(string(data)) == tc.output })
			if err := tc.emit(r.Writer("out"), embargo.NewSecret(string(r.Canary()))); err != nil {
				t.Fatal("output failed")
			}
			r.Check()
		})
		writeTable("| [" + tc.name + "](" + outputSource(t, "compatibility_integration_test.go", tc.name) + ") | `" + tc.output + "` |\n")
	}
	for _, tc := range []struct {
		check  func(*testing.T)
		name   string
		call   string
		result string
		source string
		symbol string
	}{
		{name: "OTel SDK", call: "an exported span event and raw RecordError", result: `{"Key":"key","Value":{"Type":"STRING","Value":"[REDACTED]"}}`, source: "telemetry_integration_test.go", symbol: "checkOTelAcceptance", check: checkOTelAcceptance},
		{name: "Sentry", call: "Secret in scope context, CaptureException and Recover", result: `"signing":{"key":"[REDACTED]"}`, source: "sentry_integration_test.go", symbol: "checkSentryAcceptance", check: checkSentryAcceptance},
		{name: "HTTP", call: "a real handler writing status, headers, body and trailers", result: "[REDACTED]", source: "compatibility_integration_test.go", symbol: "checkHTTPOutput", check: checkHTTPOutput},
		{name: "Child panic", call: "panic(secret) in a real test subprocess", result: "panic: [REDACTED]", source: "compatibility_integration_test.go", symbol: "checkChildOutput", check: checkChildOutput},
	} {
		t.Run(tc.name, func(t *testing.T) { t.Parallel(); tc.check(t) })
		writeTable("| [" + tc.name + "](" + outputSource(t, tc.source, tc.symbol) + ") | `" + tc.result + "` |\n")
	}
	syncReadmeTable(t, "tested-outputs", table.String())
}

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

// omitTime makes the documented log bytes reproducible across runs.
func omitTime(_ []string, attr slog.Attr) slog.Attr {
	if attr.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return attr
}

// outputSource derives GitHub line ranges from the tested source, never a hand-maintained number.
func outputSource(t *testing.T, path, symbol string) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target ast.Node
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.FuncDecl:
			if n.Name.Name == symbol {
				target = n
				return false
			}
		case *ast.CompositeLit:
			for _, elt := range n.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "name" {
					continue
				}
				value, ok := kv.Value.(*ast.BasicLit)
				if !ok {
					continue
				}
				name, err := strconv.Unquote(value.Value)
				if err == nil && name == symbol {
					target = n
					return false
				}
			}
		}
		return true
	})
	if target == nil {
		t.Fatal("output evidence symbol missing")
	}
	return fmt.Sprintf("https://github.com/nao1215/embargo/blob/main/tests/%s#L%d-L%d", path, fset.Position(target.Pos()).Line, fset.Position(target.End()).Line)
}
