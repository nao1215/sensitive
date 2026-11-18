package tests

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"connectrpc.com/connect"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v5"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
	"pgregory.net/rapid"

	"github.com/nao1215/embargo"
	embargologrus "github.com/nao1215/embargo/adapters/logrus"
	embargootel "github.com/nao1215/embargo/adapters/otel"
	embargosentry "github.com/nao1215/embargo/adapters/sentry"
	embargozap "github.com/nao1215/embargo/adapters/zap"
	embargozerolog "github.com/nao1215/embargo/adapters/zerolog"
	"github.com/nao1215/embargo/embargotest"
	"github.com/nao1215/embargo/tests/domain"
)

// Prototype only: a name rule cannot see masking handler configuration or
// arbitrary domain formatting contracts. Keep the measured counterexamples.
func TestSecretNameAnalyzerPrototype(t *testing.T) {
	t.Parallel()
	loaded, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps, Dir: "testdata/analyzerprobe"}, ".")
	if err != nil || len(loaded) != 1 {
		t.Fatal("prototype package load failed")
	}
	pkg := loaded[0]
	if len(pkg.Errors) > 0 {
		t.Fatal(pkg.Errors)
	}
	var diagnostics []analysis.Diagnostic
	analyzer := &analysis.Analyzer{Name: "embargoprototype", Doc: "Prototype of a logger argument name rule.", Run: runSecretNamePrototype}
	pass := &analysis.Pass{Analyzer: analyzer, Fset: pkg.Fset, Files: pkg.Syntax, Pkg: pkg.Types, TypesInfo: pkg.TypesInfo, Report: func(d analysis.Diagnostic) { diagnostics = append(diagnostics, d) }}
	if _, err := analyzer.Run(pass); err != nil {
		t.Fatal(err)
	}
	// Two intended findings and three safe uses: 40% precision on this adversarial
	// fixture, plus an opaque-name false negative. Do not publish this as a linter.
	if len(diagnostics) != 5 {
		t.Fatalf("prototype changed: %d diagnostics", len(diagnostics))
	}
}

//nolint:gocognit // Prototype walks only direct argument names and intentionally exposes its limits.
func runSecretNamePrototype(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := selector.Sel.Name
			if name != "Info" && name != "Error" && name != "Warn" && name != "Debug" {
				return true
			}
			function, ok := pass.TypesInfo.Uses[selector.Sel].(*types.Func)
			if !ok || function.Pkg() == nil || function.Pkg().Path() != "log/slog" {
				return true
			}
			for _, arg := range call.Args {
				var name string
				switch value := arg.(type) {
				case *ast.Ident:
					name = value.Name
				case *ast.SelectorExpr:
					name = value.Sel.Name
				}
				switch name {
				case comparisonPasswordKey, "Password", scenarioTokenKey, "Token", "secret", "Secret":
				default:
					continue
				}
				if named, ok := pass.TypesInfo.TypeOf(arg).(*types.Named); ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "github.com/nao1215/embargo" && named.Obj().Name() == "Secret" {
					continue
				}
				pass.Reportf(arg.Pos(), "sensitive name passed to logger")
			}
			return true
		})
	}
	return struct{}{}, nil
}

//nolint:goconst // The table shows and verifies literal output bytes for each logger.
func TestCompatibilityTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		emit   func(io.Writer, embargo.Secret[string]) error
		name   string
		call   string
		output string
	}{
		{name: "fmt", output: "embargo.Secret[string]([REDACTED])", call: "`fmt.Fprintf(w, \"%+#v\", secret)`", emit: func(w io.Writer, s embargo.Secret[string]) error { _, err := fmt.Fprintf(w, "%+#v", s); return err }},
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
		writeTable("| [" + tc.name + "](" + outputSource(t, "integrations_test.go", tc.name) + ") | `" + tc.output + "` |\n")
	}
	for _, tc := range []struct {
		check  func(*testing.T)
		name   string
		call   string
		result string
		source string
		symbol string
	}{
		{name: "OTel SDK", call: "an exported span event and raw RecordError", result: otelOutputExcerpt, source: "integrations_test.go", symbol: "checkOTelAcceptance", check: checkOTelAcceptance},
		{name: "Sentry", call: "Secret in scope context, CaptureException and Recover", result: sentryOutputExcerpt, source: "integrations_test.go", symbol: "checkSentryAcceptance", check: checkSentryAcceptance},
		{name: "HTTP", call: "a real handler writing status, headers, body and trailers", result: "[REDACTED]", source: "integrations_test.go", symbol: "checkHTTPOutput", check: checkHTTPOutput},
		{name: "Child panic", call: "panic(secret) in a real test subprocess", result: "panic: [REDACTED]", source: "integrations_test.go", symbol: "checkChildOutput", check: checkChildOutput},
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

// A connector avoids registering a global SQL driver and supplies a real Rows
// path with a plain string. The application's domain model imports no wrapper.
type canaryConnector struct{ value string }

func (c canaryConnector) Connect(context.Context) (driver.Conn, error) {
	return &canaryConnection{value: c.value}, nil
}

func (canaryConnector) Driver() driver.Driver { return canaryDriver{} }

type canaryDriver struct{}

func (canaryDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type canaryConnection struct{ value string }

func (c *canaryConnection) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &canaryRows{value: c.value}, nil
}

func (*canaryConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unavailable")
}

func (*canaryConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("transaction unavailable")
}

func (*canaryConnection) Close() error { return nil }

type canaryRows struct {
	value string
	done  bool
}

func (*canaryRows) Columns() []string { return []string{comparisonPasswordKey} }

func (*canaryRows) Close() error { return nil }

func (r *canaryRows) Next(values []driver.Value) error {
	if r.done {
		return io.EOF
	}
	values[0] = r.value
	r.done = true
	return nil
}

func TestDatabaseCanaryInjection(t *testing.T) {
	t.Parallel()
	r := embargotest.New(t)
	db := sql.OpenDB(canaryConnector{value: string(r.Canary())})
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	var password string
	if err := db.QueryRowContext(t.Context(), "select password from config").Scan(&password); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(r.Writer("db/log"), nil), embargo.NewScanner()))
	logger.Info("loaded", slog.String(comparisonPasswordKey, password))
	r.ExpectJSON("db/log", nil, map[string]string{comparisonPasswordKey: "[REDACTED]"}, 1)
	r.Check()
}

func TestHTTPStateProperties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		operations := rapid.SliceOfN(rapid.IntRange(0, 4), 0, 30).Draw(rt, "operations")
		probe := &observationTB{TB: t}
		r := embargotest.New(probe)
		actual := r.HTTP("http")
		expected := httptest.NewRecorder()
		for _, op := range operations {
			for _, writer := range []http.ResponseWriter{actual, expected} {
				switch op {
				case 0:
					writer.Header().Set("X-State", "changed")
				case 1:
					if _, err := writer.Write([]byte("data")); err != nil {
						rt.Fatal("write failed")
					}
				case 2:
					writer.WriteHeader(http.StatusCreated)
				case 3:
					f, ok := writer.(http.Flusher)
					if !ok {
						rt.Fatal("flusher missing")
					}
					f.Flush()
				case 4:
					writer.Header().Set("X-Other", "value")
				}
			}
		}
		result := expected.Result()
		if err := result.Body.Close(); err != nil {
			rt.Fatal("close failed")
		}
		r.Expect("http/body", func(data []byte) bool { return bytes.Equal(data, expected.Body.Bytes()) })
		r.Expect("http/status", func(data []byte) bool { return string(data) == strconv.Itoa(result.StatusCode) })
		r.Expect("http/headers", func(data []byte) bool {
			var h http.Header
			return json.Unmarshal(data, &h) == nil && reflect.DeepEqual(h, result.Header)
		})
		if !r.Check() {
			rt.Fatal("HTTP state model disagrees")
		}
		probe.finish()
	})
}

func TestHTTPRedirectAndErrorLeakPaths(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{scenarioRedirect, scenarioErrorKey, "clean-response"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe)
			w := r.HTTP("response")
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
			switch mode {
			case scenarioRedirect:
				http.Redirect(w, req, "/login?token="+string(r.Canary()), http.StatusFound)
			case scenarioErrorKey:
				http.Error(w, string(r.Canary()), http.StatusInternalServerError)
			default:
				http.Error(w, "request failed", http.StatusInternalServerError)
			}
			r.Expect("response/body", func(data []byte) bool { return len(data) > 0 })
			if r.Check() != (mode == "clean-response") {
				t.Fatal("wrong HTTP verdict")
			}
			probe.finish()
		})
	}
}

//nolint:gocognit // Exercise the complete type, encoder and formatting cross-product under one shrinker.
func TestSecretProperties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		raw := append([]byte("fake-property-canary-"), rapid.SliceOfN(rapid.Byte(), 16, 100).Draw(t, "secret")...)
		text := string(raw)
		secret := embargo.NewSecret(text)
		var input embargo.Input[string]
		if err := input.UnmarshalText(raw); err != nil {
			t.Fatal("input failed")
		}
		var binary embargo.Input[[]byte]
		if err := binary.UnmarshalText(raw); err != nil {
			t.Fatal("byte input failed")
		}
		bytesSecret := embargo.NewSecret(raw)
		var array [32]byte
		copy(array[:], raw)
		arraySecret := embargo.NewSecret(array)
		forms := []any{
			secret, &secret, input, &input, binary, &binary, bytesSecret, arraySecret,
			struct{ Public embargo.Secret[string] }{secret},
			struct{ private embargo.Secret[string] }{secret},
			[]any{secret},
			map[string]any{"token": input},
			struct{ embargo.Secret[string] }{secret},
			struct{ private embargo.Input[string] }{input},
			fmt.Errorf("wrapped display: %v", secret),
		}
		flags := rapid.SampledFrom([]string{"", "+", "#", "-", " ", "0", "+#020.12", "-# 30.4"}).Draw(t, "flags")
		needles := make([]string, 0, 11)
		needles = append(needles, text, hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw)), base64.StdEncoding.EncodeToString(raw), fmt.Sprintf("%v", raw), string(array[:]), hex.EncodeToString(array[:]), strings.ToUpper(hex.EncodeToString(array[:])), base64.StdEncoding.EncodeToString(array[:]), fmt.Sprintf("%v", array))
		escaped, err := json.Marshal(text)
		if err != nil {
			t.Fatal("fixture encoding failed")
		}
		needles = append(needles, string(escaped[1:len(escaped)-1]))
		check := func(output string) {
			for _, needle := range needles {
				if strings.Contains(output, needle) {
					t.Fatal("secret representation found")
				}
			}
		}
		for _, form := range forms {
			for _, verb := range "vbcdoOqxXUeEfFgGstpT%z" {
				check(fmt.Sprintf("%"+flags+string(verb), form))
			}
			j, err := json.Marshal(form)
			if err != nil {
				t.Fatal("JSON encoding failed")
			}
			check(string(j))
			for _, jsonHandler := range []bool{false, true} {
				var out bytes.Buffer
				var handler slog.Handler = slog.NewTextHandler(&out, nil)
				if jsonHandler {
					handler = slog.NewJSONHandler(&out, nil)
				}
				slog.New(handler).With("attached", form).WithGroup("group").Info("event", "value", form)
				check(out.String())
			}
		}
		for _, form := range []any{secret, input} {
			encoded, err := xml.Marshal(struct {
				Value   any      `xml:"value"`
				XMLName xml.Name `xml:"record"`
			}{Value: form})
			if err != nil {
				t.Fatal("XML encoding failed")
			}
			check(string(encoded))
			tpl, err := template.New("value").Parse("{{.}}")
			if err != nil {
				t.Fatal("template parse failed")
			}
			var out bytes.Buffer
			if err := tpl.Execute(&out, form); err != nil {
				t.Fatal("template failed")
			}
			check(out.String())
		}
	})
}

func TestFmtDifferential(t *testing.T) {
	t.Parallel()
	s := embargo.NewSecret("fake-differential-canary")
	var input embargo.Input[string]
	if err := input.UnmarshalText([]byte("fake-differential-canary")); err != nil {
		t.Fatal(err)
	}
	const flags = "+#- 0"
	for mask := range 1 << len(flags) {
		var selected strings.Builder
		for i := range len(flags) {
			if mask&(1<<i) != 0 {
				if _, err := selected.WriteString(string(flags[i])); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, width := range []string{"", "20.8"} {
			for _, verb := range "vbcdoOqxXUeEfFgGstz" {
				format := "%" + selected.String() + width + string(verb)
				want := "[REDACTED]"
				if verb == 'v' && strings.Contains(selected.String(), "#") {
					want = "embargo.Secret[string]([REDACTED])"
				}
				if fmt.Sprintf(format, s) != want || fmt.Sprintf(format, input) != "[REDACTED]" {
					t.Fatal("differential marker mismatch")
				}
			}
		}
	}
}

func TestConcurrentCoreReads(t *testing.T) {
	t.Parallel()
	s := embargo.NewSecret([32]byte{1, 2, 3})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 200 {
				if s.Reveal()[0] != 1 {
					t.Error("copy changed")
				}
				if s.String() != "[REDACTED]" {
					t.Error("display changed")
				}
			}
		})
	}
	wg.Wait()
}

const sentryOutputExcerpt = `"signing":{"key":"[REDACTED]"}`

// bufferedTransport is a sentry.Transport that holds events until Flush and
// then writes the JSON the real SDK would send, one event per line. Holding
// until Flush mirrors HTTPTransport, so a missing Flush loses the events.
type bufferedTransport struct {
	w      io.Writer
	events []*sentry.Event
	mu     sync.Mutex
}

func (b *bufferedTransport) Configure(sentry.ClientOptions) {}

func (b *bufferedTransport) Close() {}

func (b *bufferedTransport) SendEvent(event *sentry.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event)
}

func (b *bufferedTransport) Flush(time.Duration) bool {
	return b.FlushWithContext(context.Background())
}

func (b *bufferedTransport) FlushWithContext(context.Context) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	encoder := json.NewEncoder(b.w)
	for _, event := range b.events {
		if err := encoder.Encode(event); err != nil {
			return false
		}
	}
	b.events = nil
	return true
}

// sentryEvent uses an application-owned code and the SDK's argument-free stack representation.
func sentryEvent(d failure) *sentry.Event {
	stack := sentry.NewStacktrace()
	// Exercise a long build path on every checkout, including short CI paths.
	for i := range stack.Frames {
		stack.Frames[i].AbsPath = "/tmp/BuildCache-20261116/Projects/PaymentGateway/RequestDiagnostics/SentryIntegration_test.go"
		stack.Frames[i].Filename = "SentryIntegration_test.go"
	}
	event := sentry.NewEvent()
	event.Level = sentry.LevelError
	event.Message = d.message
	event.Tags = map[string]string{"code": d.code}
	event.Exception = []sentry.Exception{{Type: d.code, Value: d.message, Stacktrace: stack}}
	return event
}

//nolint:gocognit,goconst // Keep the expected outputs and failure modes together in this acceptance matrix.
func checkSentryAcceptance(t *testing.T) {
	t.Helper()
	for _, mode := range []string{"safe", "raw-error", "raw-recover", "raw-context", "missing-flush", "regressed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe)
			d := signingFailed()
			transport := &bufferedTransport{w: r.Writer("sentry")}
			// A fixed release keeps the SDK from deriving one from git describe,
			// whose abbreviated commit hash changes the scanned output per commit.
			client, err := sentry.NewClient(sentry.ClientOptions{Transport: transport, AttachStacktrace: true, Release: "acceptance"})
			if err != nil {
				t.Fatal("client setup failed")
			}
			// The client starts batch goroutines; Close stops them so goleak
			// sees none left after the test.
			defer client.Close()
			hub := sentry.NewHub(client, sentry.NewScope())
			key := embargo.NewSecret(string(r.Canary()))
			// A Secret in scope data is marshaled with the event; the context
			// path must print the marker, not the key.
			hub.Scope().SetContext("signing", sentry.Context{"key": key})

			switch mode {
			case "raw-error":
				hub.CaptureException(fmt.Errorf("request: %w", errors.Join(errors.New("database unavailable"), errors.New("token="+key.Reveal()))))
			case "raw-recover":
				hub.Recover("signing failed: " + key.Reveal())
			case "raw-context":
				hub.Scope().SetContext("signing_raw", sentry.Context{"key": key.Reveal()})
				hub.CaptureEvent(sentryEvent(d))
			case "regressed":
				hub.CaptureEvent(sentryEvent(withheld()))
			default:
				hub.CaptureEvent(sentryEvent(d))
			}
			if mode != "missing-flush" && !hub.Flush(time.Second) {
				t.Fatal("flush failed")
			}

			r.Expect("sentry", func(data []byte) bool {
				if mode == "raw-error" {
					return json.Valid(data) && bytes.Contains(data, []byte("request:")) && bytes.Contains(data, r.Canary())
				}
				if !bytes.Contains(data, []byte(sentryOutputExcerpt)) {
					return false
				}
				var event struct {
					Message   string                    `json:"message"`
					Tags      map[string]string         `json:"tags"`
					Contexts  map[string]map[string]any `json:"contexts"`
					Exception []struct {
						Type       string `json:"type"`
						Value      string `json:"value"`
						Stacktrace struct {
							Frames []struct {
								Function string `json:"function"`
								Lineno   int    `json:"lineno"`
							} `json:"frames"`
						} `json:"stacktrace"`
					} `json:"exception"`
				}
				if json.Unmarshal(data, &event) != nil || len(event.Exception) != 1 {
					return false
				}

				ex := event.Exception[0]
				frames := ex.Stacktrace.Frames
				return ex.Type == d.code && ex.Value == d.message && event.Tags["code"] == d.code &&
					event.Contexts["signing"]["key"] == "[REDACTED]" &&
					len(frames) > 0 && frames[len(frames)-1].Function != "" && frames[len(frames)-1].Lineno > 0
			})
			if r.Check() != (mode == "safe") {
				t.Fatalf("Sentry detector returned wrong verdict: %v", probe.messages)
			}
			if mode == "raw-error" {
				messages := strings.Join(probe.messages, "\n")
				if !strings.Contains(messages, "the fake secret appeared") || strings.Contains(messages, "content expectation") {
					t.Fatal("wrapped error must fail for a leak, not a missing export", probe.messages)
				}
			}
			probe.finish()
		})
	}
}

// observationTB catches intentional failures without weakening the detector.
// failure is a code and message the application defines for a failure, as a
// service would log instead of the raw error.
type failure struct{ code, message string }

func signingFailed() failure { return failure{code: "signing_failed", message: "Signing failed"} }

func withheld() failure { return failure{code: "error", message: "Error details withheld"} }

func (f failure) fields() map[string]string {
	return map[string]string{"code": f.code, "message": f.message}
}

type observationTB struct {
	testing.TB

	cleanup  []func()
	messages []string
	errors   int
}

func (t *observationTB) Error(args ...any) {
	t.errors++
	t.messages = append(t.messages, fmt.Sprint(args...))
}

func (t *observationTB) Cleanup(f func()) { t.cleanup = append(t.cleanup, f) }

func (t *observationTB) finish() {
	for _, v := range slices.Backward(t.cleanup) {
		v()
	}
}

func TestSigningAcceptance(t *testing.T) {
	t.Parallel()
	//nolint:goconst // Independent acceptance scenarios keep their literal expected results local.
	for _, mode := range []string{"safe", "leak", "missing", "regressed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe)
			reported := failure{"signing_unavailable", "Signing is temporarily unavailable"}
			r.ExpectJSON("logs", []string{"failure"}, reported.fields(), 1)
			r.Expect("response", func(b []byte) bool { return bytes.Equal(b, []byte("503 signing_unavailable")) })
			var request struct {
				Seed embargo.Input[string] `json:"seed"`
			}
			input, err := json.Marshal(map[string]string{"seed": string(r.Canary())})
			if err != nil {
				t.Fatal("fixture encoding failed")
			}
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal("input decode failed")
			}
			key := request.Seed.Secret()
			raw := &url.Error{Op: "sign", URL: "https://signer.invalid/?seed=" + key.Reveal(), Err: errors.New("offline")}
			logger := slog.New(slog.NewJSONHandler(r.Writer("logs"), nil))
			logged := reported
			if mode == "regressed" {
				logged = withheld()
			}
			if mode != "missing" {
				logger.Error("signing request failed", "operation", "sign", "key", key,
					"failure", slog.GroupValue(slog.String("code", logged.code), slog.String("message", logged.message)))
				if _, err := r.Writer("response").Write([]byte("503 signing_unavailable")); err != nil {
					t.Fatal("write failed")
				}
			}
			if mode == "leak" {
				logger.Error("transport failed", "error", raw)
			}
			passed := r.Check()
			probe.finish()
			if passed != (mode == "safe") || (probe.errors == 0) != (mode == "safe") {
				t.Fatal("acceptance detector returned the wrong verdict")
			}
		})
	}
}

func TestSigningKeyRepresentations(t *testing.T) {
	t.Parallel()
	for _, leak := range []bool{false, true} {
		probe := &observationTB{TB: t}
		r := embargotest.New(probe)
		rawKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), r.Canary())
		if err != nil {
			t.Fatal("fake key fixture invalid")
		}
		key := embargo.NewSecret(rawKey)
		digest := sha256.Sum256([]byte("public transaction fixture"))
		signature, err := ecdsa.SignASN1(rand.Reader, key.Reveal(), digest[:])
		if err != nil || !ecdsa.VerifyASN1(&key.Reveal().PublicKey, digest[:], signature) {
			t.Fatal("signing fixture failed")
		}
		r.Expect("logs", func(data []byte) bool { return bytes.Contains(data, []byte("signing completed")) })
		logger := slog.New(slog.NewJSONHandler(r.Writer("logs"), nil))
		if leak {
			logger.Info("signing completed", "key", key.Reveal())
		} else {
			logger.Info("signing completed", "key", key, "seed", embargo.NewSecret([32]byte(r.Canary())))
		}
		if r.Check() == leak {
			t.Fatal("signing key detector returned wrong verdict")
		}
		probe.finish()
	}
}

const (
	loggerLogrus  = "logrus"
	loggerSlog    = "slog"
	loggerZap     = "zap"
	loggerZerolog = "zerolog"
)

func TestLoggerKeyContextDifferential(t *testing.T) {
	const clientSecretKey = "client_secret"
	t.Parallel()
	for _, fixture := range []struct {
		value, want any
		key         string
	}{
		{731, referenceMarker, "cvv"},
		{"opaque-client-value", referenceMarker, clientSecretKey},
		{true, referenceMarker, clientSecretKey},
		{nil, referenceMarker, clientSecretKey},
		{12345678, referenceMarker, "bank account"},
		{"12/29", referenceMarker, "expiry"},
		{7, float64(7), metamorphicCountKey},
		{"retained", "retained", "status"},
		{true, true, "paid"},
	} {
		t.Run(fixture.key, func(t *testing.T) {
			t.Parallel()
			scanner := embargo.NewScanner()
			raw, err := json.Marshal(map[string]any{fixture.key: fixture.value})
			if err != nil {
				t.Fatal(err)
			}
			masked, err := scanner.MaskJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			expected := loggerField(t, masked, fixture.key)
			if !reflect.DeepEqual(expected, fixture.want) {
				t.Fatalf("MaskJSON got %v want %v", expected, fixture.want)
			}
			for _, name := range []string{loggerSlog, loggerZap, loggerZerolog, loggerLogrus} {
				out := loggerOutput(t, scanner, name, fixture.key, fixture.value)
				if got := loggerField(t, out, fixture.key); !reflect.DeepEqual(got, expected) {
					t.Errorf("%s got %v want %v", name, got, expected)
				}
			}
		})
	}
}

func loggerField(t *testing.T, data []byte, key string) any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	value, ok := fields[key]
	if !ok {
		t.Fatalf("missing %q in %s", key, data)
	}
	return value
}

func loggerOutput(t *testing.T, scanner *embargo.Scanner, name, key string, value any) []byte {
	t.Helper()
	var out bytes.Buffer
	switch name {
	case loggerSlog:
		slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), scanner)).Info("event", key, value)
	case loggerZap:
		sink := embargozap.NewWriteSyncer(zapcore.AddSync(&out), scanner)
		logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{MessageKey: "msg"}), sink, zap.InfoLevel))
		field := zap.Any(key, value)
		if raw, ok := value.(json.RawMessage); ok {
			// Since Go 1.27 json.RawMessage is a fmt.Stringer, which zap.Any logs
			// as a string; Reflect keeps the encoded JSON value in the record.
			field = zap.Reflect(key, raw)
		}
		logger.Info("event", field)
		if err := logger.Sync(); err != nil {
			t.Fatal(err)
		}
	case loggerZerolog:
		sink := embargozerolog.NewWriter(&out, scanner)
		logger := zerolog.New(sink)
		logger.Info().Interface(key, value).Msg("event")
		if err := sink.Close(); err != nil {
			t.Fatal(err)
		}
	case loggerLogrus:
		logger := logrus.New()
		logger.SetOutput(&out)
		logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{}, scanner))
		logger.WithField(key, value).Info("event")
	}
	return out.Bytes()
}

func TestLoggerMaskedKeyCollisions(t *testing.T) {
	t.Parallel()
	for _, value := range []any{
		map[string]any{"a@example.com": float64(4111111111111111), "z@example.com": 7},
		struct {
			First  float64 `json:"first"`
			Second int     `json:"second"`
		}{4111111111111111, 7},
	} {
		scanner := embargo.NewScanner(embargo.WithDetector(collisionKeys{}))
		raw, err := json.Marshal(map[string]any{"data": value})
		if err != nil {
			t.Fatal(err)
		}
		safe, err := scanner.MaskJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"MaskJSON", loggerSlog, loggerZap, loggerZerolog, loggerLogrus} {
			out := safe
			if name != "MaskJSON" {
				out = loggerOutput(t, scanner, name, "data", value)
			}
			got := loggerField(t, out, "data")
			want := map[string]any{referenceMarker: float64(7)}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s collision got %#v want %#v", name, got, want)
			}
		}
	}
}

type collisionKeys struct{}

func (collisionKeys) Scan(data []byte) []embargo.Finding {
	if string(data) == "first" || string(data) == "second" {
		return []embargo.Finding{{Kind: "collision-key", Start: 0, End: len(data), Confidence: 1}}
	}
	return nil
}

const otelOutputExcerpt = `{"Key":"key","Value":{"Type":"STRING","Value":"[REDACTED]"}}`

//nolint:gocognit,gocyclo // Keep the expected outputs and failure modes together in this acceptance matrix.
func checkOTelAcceptance(t *testing.T) {
	t.Helper()
	for _, mode := range []string{"safe", "raw-error", "missing-flush", "regressed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe)
			d := signingFailed()
			exporter := tracetest.NewInMemoryExporter()
			recorder := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(time.Minute)), sdktrace.WithSpanProcessor(recorder))
			defer func() {
				if err := provider.Shutdown(context.Background()); err != nil {
					t.Error("SDK shutdown failed")
				}
			}()
			_, span := provider.Tracer("embargo-test").Start(context.Background(), "signer.sign")
			if mode == "raw-error" {
				span.RecordError(fmt.Errorf("request: %w", errors.Join(errors.New("database unavailable"), errors.New("token="+string(r.Canary())))), trace.WithStackTrace(true))
			} else {
				selected := d
				if mode == "regressed" {
					selected = withheld()
				}
				span.AddEvent("signer.failure", trace.WithAttributes(attribute.String("code", selected.code), attribute.String("message", selected.message), attribute.String("key", embargo.NewSecret(string(r.Canary())).String())))
				span.SetStatus(codes.Error, selected.message)
			}
			span.End()
			if len(recorder.Ended()) != 1 {
				t.Fatal("real span recorder did not receive event")
			}
			if mode != "missing-flush" {
				if err := provider.ForceFlush(context.Background()); err != nil {
					t.Fatal("SDK flush failed")
				}
			}
			// Marshal the entire SDK export, including resource, scope, status and events.
			if err := json.NewEncoder(r.Writer("sdk")).Encode(exporter.GetSpans()); err != nil {
				t.Fatal("export serialization failed")
			}
			r.Expect("sdk", func(data []byte) bool {
				if mode == "raw-error" {
					return json.Valid(data) && bytes.Contains(data, []byte("request:")) && bytes.Contains(data, r.Canary())
				}
				if !bytes.Contains(data, []byte(otelOutputExcerpt)) {
					return false
				}
				//nolint:tagliatelle // The OTel SpanStub JSON uses SDK field names.
				var spans []struct {
					SpanContext struct {
						TraceID string `json:"TraceID"`
						SpanID  string `json:"SpanID"`
					} `json:"SpanContext"`
					Name   string `json:"Name"`
					Events []struct {
						Attributes []struct {
							Key   string `json:"Key"`
							Value struct {
								Type  string `json:"Type"`
								Value string `json:"Value"`
							} `json:"Value"`
						} `json:"Attributes"`
					} `json:"Events"`
					Status struct {
						Code codes.Code `json:"Code"`
					} `json:"Status"`
				}
				if json.Unmarshal(data, &spans) != nil || len(spans) != 1 || spans[0].SpanContext.TraceID != span.SpanContext().TraceID().String() || spans[0].SpanContext.SpanID != span.SpanContext().SpanID().String() || spans[0].Name != "signer.sign" || len(spans[0].Events) != 1 || spans[0].Status.Code != codes.Error {
					return false
				}
				attrs := make(map[string]string)
				for _, a := range spans[0].Events[0].Attributes {
					attrs[a.Key] = a.Value.Value
				}
				return attrs["code"] == d.code && attrs["message"] == d.message && attrs["key"] == "[REDACTED]"
			})
			if r.Check() != (mode == "safe") {
				t.Fatal("telemetry detector returned wrong verdict")
			}
			if mode == "raw-error" {
				messages := strings.Join(probe.messages, "\n")
				if !strings.Contains(messages, "the fake secret appeared") || strings.Contains(messages, "content expectation") {
					t.Fatal("wrapped error must fail for a leak, not a missing export", probe.messages)
				}
			}
			probe.finish()
		})
	}
}

// sdkLogCapture observes the complete exported application payload, scope and
// resource in memory; no SDK network transport or global provider is installed.
type sdkLogCapture struct{ writer io.Writer }

func (c *sdkLogCapture) Export(_ context.Context, records []sdklog.Record) error {
	for i := range records {
		record := &records[i]
		attributes := map[string]any{}
		record.WalkAttributes(func(kv attribute.KeyValue) bool { attributes[string(kv.Key)] = kv.Value.String(); return true })
		payload := map[string]any{"body": record.Body().String(), "attributes": attributes, "resource": record.Resource().Attributes(), "scope": record.InstrumentationScope(), "severity": record.SeverityText(), "trace_id": record.TraceID().String(), "span_id": record.SpanID().String()}
		if err := json.NewEncoder(c.writer).Encode(payload); err != nil {
			return err
		}
	}
	return nil
}

func (*sdkLogCapture) Shutdown(context.Context) error { return nil }

func (*sdkLogCapture) ForceFlush(context.Context) error { return nil }

func TestOTelLogOutputGuard(t *testing.T) {
	t.Parallel()
	for _, safe := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw-credential", true: "masked"}[safe], func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe, embargotest.WithScanner(embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))))
			provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(&sdkLogCapture{writer: r.Writer("otel/log")})))
			defer func() {
				if err := provider.Shutdown(context.Background()); err != nil {
					t.Error("shutdown failed")
				}
			}()
			text := errors.Join(errors.New("database: postgres://reader:forgotten@db.example/orders"), errors.New("token=opaque-service-value")).Error()
			if safe {
				scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
				text = embargo.Mask(text, scanner.ScanString(text))
			}
			var record otellog.Record
			record.SetBody(attribute.StringValue(text))
			record.AddAttributes(attribute.String("operation", "checkout"))
			provider.Logger("embargo-test").Emit(t.Context(), record)
			if err := provider.ForceFlush(t.Context()); err != nil {
				t.Fatal(err)
			}
			r.Expect("otel/log", func(data []byte) bool { return len(data) > 0 })
			if r.Check() != safe {
				t.Fatal("wrong OTel log verdict")
			}
			probe.finish()
		})
	}
}

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

const (
	loggerGroupText = "slog-group-text"
	loggerText      = "slog-text"
)

func TestLoggerJoinedPathProperty(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner()
	rapid.Check(t, func(rt *rapid.T) {
		local := "user" + strconv.Itoa(rapid.IntRange(1, 999999).Draw(rt, "mailbox"))
		for _, parts := range [][]string{{local + "@example", "com"}, {local, "tag@example", "co", "uk"}} {
			for _, name := range []string{loggerSlog, loggerText, "slog-group-json", loggerGroupText, loggerZap, loggerZerolog, loggerLogrus} {
				var out bytes.Buffer
				emitJoinedPath(t, &out, scanner, name, parts)
				got := out.String()
				if !strings.Contains(got, referenceMarker) {
					rt.Fatalf("%s split path missing mask: %s", name, got)
				}
				for _, part := range parts {
					if strings.Contains(got, part) {
						rt.Fatalf("%s split path retains %s: %s", name, part, got)
					}
				}
			}
		}
	})
}

func emitJoinedPath(t *testing.T, out io.Writer, scanner *embargo.Scanner, name string, parts []string) {
	t.Helper()
	last := len(parts) - 1
	switch name {
	case "slog-group-json", loggerGroupText:
		var handler slog.Handler = slog.NewJSONHandler(out, nil)
		if name == loggerGroupText {
			handler = slog.NewTextHandler(out, nil)
		}
		attr := slog.String(parts[last], "x")
		for i := last - 1; i >= 0; i-- {
			attr = slog.Attr{Key: parts[i], Value: slog.GroupValue(attr)}
		}
		slog.New(embargo.NewSlogHandler(handler, scanner)).LogAttrs(t.Context(), slog.LevelInfo, "event", attr)
	case loggerSlog, loggerText:
		var handler slog.Handler = slog.NewJSONHandler(out, nil)
		if name == loggerText {
			handler = slog.NewTextHandler(out, nil)
		}
		logger := slog.New(embargo.NewSlogHandler(handler, scanner))
		for _, part := range parts[:last] {
			logger = logger.WithGroup(part)
		}
		logger.Info("event", parts[last], "x")
	case loggerZap:
		sink := embargozap.NewWriteSyncer(zapcore.AddSync(out), scanner)
		logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), sink, zap.DebugLevel))
		for _, part := range parts[:last] {
			logger = logger.With(zap.Namespace(part))
		}
		logger.Info("event", zap.String(parts[last], "x"))
	case loggerZerolog:
		logger := zerolog.New(embargozerolog.NewWriter(out, scanner))
		dict := zerolog.Dict().Str(parts[last], "x")
		for i := last - 1; i > 0; i-- {
			dict = zerolog.Dict().Dict(parts[i], dict)
		}
		logger.Info().Dict(parts[0], dict).Msg("event")
	case loggerLogrus:
		logger := logrus.New()
		logger.SetOutput(out)
		logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{}, scanner))
		value := map[string]any{parts[last]: "x"}
		for i := last - 1; i > 0; i-- {
			value = map[string]any{parts[i]: value}
		}
		logger.WithField(parts[0], value).Info("event")
	default:
		t.Fatal("unknown logger")
	}
}

func checkSDKNumberLexeme(t *testing.T, scanner *embargo.Scanner, key, lexeme string) {
	t.Helper()
	event := sentry.NewEvent()
	event.Contexts = map[string]sentry.Context{"numbers": {key: json.Number(lexeme)}}
	safe := embargosentry.NewBeforeSend(scanner)(event, nil)
	if safe == nil || safe.Contexts["numbers"][key] != referenceMarker {
		t.Fatalf("Sentry retained a number lexeme: %s", lexeme)
	}
	var out bytes.Buffer
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(embargootel.NewLogExporter(&sdkLogCapture{writer: &out}, scanner))))
	var record otellog.Record
	record.SetBody(attribute.StringValue("public"))
	record.AddAttributes(attribute.String(key, lexeme))
	provider.Logger("number-property").Emit(t.Context(), record)
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	var logged struct {
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal(out.Bytes(), &logged); err != nil {
		t.Fatal(err)
	}
	if logged.Attributes[key] != referenceMarker {
		t.Fatalf("OTel log retained a number lexeme: %s", lexeme)
	}
	sink := tracetest.NewInMemoryExporter()
	span := tracetest.SpanStub{Name: "public", Attributes: []attribute.KeyValue{attribute.String(key, lexeme)}}.Snapshot()
	if err := embargootel.NewSpanExporter(sink, scanner).ExportSpans(t.Context(), []sdktrace.ReadOnlySpan{span}); err != nil {
		t.Fatal(err)
	}
	spans := sink.GetSpans()
	if len(spans) != 1 || len(spans[0].Attributes) != 1 || spans[0].Attributes[0].Value.AsString() != referenceMarker {
		t.Fatalf("OTel span retained a number lexeme: %s", lexeme)
	}
}

//nolint:gocognit // Keep every real hook in the same generated-input acceptance matrix.
func TestFreeTextHooksProperty(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner()
	rapid.Check(t, func(rt *rapid.T) {
		secret := "opaqueHookFixture" + strconv.Itoa(rapid.IntRange(1, 999999).Draw(rt, "secret")) + "Tail"
		key := rapid.SampledFrom([]string{"password", "token", "access_token", "DB_PASSWORD", "x-api-key", "Private-Token"}).Draw(rt, "key")
		header := http.Header{freeTextAuthorizationHeader: {"Bearer " + secret, "Basic " + secret}, key: {secret}}
		body, err := json.Marshal(map[string]string{key: secret})
		if err != nil {
			rt.Fatal(err)
		}
		address := "::ffff:203.0.113." + strconv.Itoa(rapid.IntRange(1, 254).Draw(rt, "octet"))
		for _, input := range []string{fmt.Sprintf("headers=%v", header), fmt.Sprintf("headers=%#v", header), fmt.Sprintf("body=%q", body), strconv.Quote(strconv.Quote(string(body))), key + "=[REDACTED]" + secret, "[" + address + "]:51234"} {
			check := func(name string, raw []byte) {
				if len(raw) == 0 || bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(".0.113.")) || !bytes.Contains(raw, []byte(referenceMarker)) {
					rt.Fatalf("%s retained text: %q", name, raw)
				}
			}
			for _, name := range []string{loggerSlog, loggerZap, loggerZerolog, loggerLogrus} {
				check(name, loggerOutput(t, scanner, name, "context", input))
				check(name+" error", freeTextErrorOutput(t, scanner, name, input))
			}
			for _, jsonHandler := range []bool{false, true} {
				var out bytes.Buffer
				var next slog.Handler = slog.NewTextHandler(&out, nil)
				if jsonHandler {
					next = slog.NewJSONHandler(&out, nil)
				}
				slog.New(embargo.NewSlogHandler(next, scanner)).Error(input, slog.Any("error", errors.New(input)))
				check("slog message", out.Bytes())
			}
			event := sentry.NewEvent()
			event.Message = input
			event.Exception = []sentry.Exception{{Value: input}}
			safe := embargosentry.NewBeforeSend(scanner)(event, nil)
			if safe == nil {
				rt.Fatal("Sentry dropped normal event")
			}
			encoded, e := json.Marshal(safe)
			if e != nil {
				rt.Fatal(e)
			}
			check("Sentry", encoded)
			var out bytes.Buffer
			provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(embargootel.NewLogExporter(&sdkLogCapture{writer: &out}, scanner))))
			var record otellog.Record
			record.SetBody(attribute.StringValue(input))
			provider.Logger("text-property").Emit(t.Context(), record)
			if shutdownErr := provider.Shutdown(t.Context()); shutdownErr != nil {
				rt.Fatal(shutdownErr)
			}
			check("OTel log", out.Bytes())
			sink := tracetest.NewInMemoryExporter()
			span := tracetest.SpanStub{Name: input, Attributes: []attribute.KeyValue{attribute.String("context", input)}}.Snapshot()
			if exportErr := embargootel.NewSpanExporter(sink, scanner).ExportSpans(t.Context(), []sdktrace.ReadOnlySpan{span}); exportErr != nil {
				rt.Fatal(exportErr)
			}
			encoded, e = json.Marshal(sink.GetSpans())
			if e != nil {
				rt.Fatal(e)
			}
			check("OTel span", encoded)
			out.Reset()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://service.invalid/", nil)
			request.RemoteAddr = "[" + address + "]:51234"
			request.Header.Set("X-Context", input)
			embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), slog.New(slog.NewJSONHandler(&out, nil)), scanner).ServeHTTP(httptest.NewRecorder(), request)
			check("HTTP", out.Bytes())
		}
	})
}

func TestMaskFuncReachesEveryHook(t *testing.T) {
	t.Parallel()
	const card, kept = "4111111111111111", "****1111"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN), embargo.WithMaskFunc(func(_ embargo.Kind, value string) string {
		return "****" + value[len(value)-4:]
	}))
	check := func(name string, raw []byte) {
		t.Helper()
		if bytes.Contains(raw, []byte(card)) || !bytes.Contains(raw, []byte(kept)) {
			t.Errorf("%s did not keep only the last four digits: %q", name, raw)
		}
	}
	for _, name := range []string{loggerSlog, loggerZap, loggerZerolog, loggerLogrus} {
		check(name, loggerOutput(t, scanner, name, "note", "paid with "+card))
		check(name+" number", loggerOutput(t, scanner, name, "card", int64(4111111111111111)))
	}
	event := sentry.NewEvent()
	event.Message = "paid with " + card
	encoded, err := json.Marshal(embargosentry.NewBeforeSend(scanner)(event, nil))
	if err != nil {
		t.Fatal(err)
	}
	check("Sentry", encoded)
	var out bytes.Buffer
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(embargootel.NewLogExporter(&sdkLogCapture{writer: &out}, scanner))))
	var record otellog.Record
	record.SetBody(attribute.StringValue("paid with " + card))
	provider.Logger("mask-func").Emit(t.Context(), record)
	if err = provider.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	check("OTel log", out.Bytes())
	sink := tracetest.NewInMemoryExporter()
	span := tracetest.SpanStub{Name: "checkout", Attributes: []attribute.KeyValue{attribute.String("note", "paid with "+card)}}.Snapshot()
	if err = embargootel.NewSpanExporter(sink, scanner).ExportSpans(t.Context(), []sdktrace.ReadOnlySpan{span}); err != nil {
		t.Fatal(err)
	}
	if encoded, err = json.Marshal(sink.GetSpans()); err != nil {
		t.Fatal(err)
	}
	check("OTel span", encoded)
	out.Reset()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://service.invalid/?card="+card, nil)
	embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), slog.New(slog.NewJSONHandler(&out, nil)), scanner).ServeHTTP(httptest.NewRecorder(), request)
	check("HTTP", out.Bytes())
}

func freeTextErrorOutput(t *testing.T, scanner *embargo.Scanner, name, input string) []byte {
	t.Helper()
	var out bytes.Buffer
	switch name {
	case loggerZerolog:
		sink := embargozerolog.NewWriter(&out, scanner)
		logger := zerolog.New(sink)
		logger.Error().Err(errors.New(input)).Msg(input)
		if err := sink.Close(); err != nil {
			t.Fatal(err)
		}
	case loggerLogrus:
		logger := logrus.New()
		logger.SetOutput(&out)
		logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{}, scanner))
		logger.WithError(errors.New(input)).Error(input)
	default:
		return loggerOutput(t, scanner, name, "error", errors.New(input))
	}
	return out.Bytes()
}

const freeTextAuthorizationHeader = "Authorization"

// Every free-text and key-value hook consumes the same generated failure shapes.
const (
	boundaryIPv4 = "203.0.113.9"
	boundaryBIC  = "DEUTDEFF"
)

func TestMaskingBoundaryHooks(t *testing.T) {
	t.Parallel()
	var grpcCases [][]string
	for n := range 3 {
		secret := fmt.Sprintf("opaqueHook%02dFixture", n)
		inputs := []struct{ text, needle string }{
			{"connection from 2001:db8::5.", "2001:db8::5"},
			{"peer ::ffff:203.0.113.9.", boundaryIPv4},
			{"Accepted connection from 203.0.113.9.", boundaryIPv4},
			{"blocked 203.0.113.9...", boundaryIPv4},
			{`{"ip":"203.0.113.9."}`, boundaryIPv4},
			{"peer 2001:db8::5: closed", "2001:db8::5"},
			{"SWIFT-Code: DEUTDEFF", boundaryBIC},
			{"swift_code=DEUTDEFF", boundaryBIC},
			{"swiftCode=DEUTDEFF", boundaryBIC},
			{"SWIFT number DEUTDEFF", boundaryBIC},
			{"password := " + secret, secret},
			{"Authorization: `Token " + secret + "` public=kept", secret},
			{"Authorization: 'Token " + secret + "' public=kept", secret},
			{"map[" + strings.Repeat("service_", 32) + "password:head " + secret + " tail public:kept]", secret},
			{"map[public:" + strings.Repeat("x", 256) + " password:head " + secret + " tail public:kept]", secret},
			{"password=`head " + secret + " tail`", secret},
			{"password: |\n  " + secret + "\n  body\npublic: retained", secret},
			{"q=password%3D" + secret + "%26user%3Dbob", secret},
			{"{DSN:{Scheme:https Opaque: User:bob:" + secret + " Host:example.com Path:/x}}", secret},
			{"user arn:jp:mynumber::123456789018: ok", "123456789018"},
			{"arn:aws:iam::1234 5678 9018:role", "1234 5678 9018"},
		}
		for _, label := range []string{"PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
			for _, header := range []string{"-----BEGIN " + label + "-----", "%2D----BEGIN " + label + "-----", "-----BEGIN " + strings.ReplaceAll(label, " ", "%20") + "-----"} {
				inputs = append(inputs, struct{ text, needle string }{header + "\n" + secret + "\n-----END " + label + "-----", secret})
			}
		}
		for _, scheme := range []string{"Bearer\t", "Token ", "Negotiate ", "Digest response=", "AWS4-HMAC-SHA256 Signature=", "'Quoted' ", "`Wrapped` ", "'\t", "`Leading\t"} {
			inputs = append(inputs, struct{ text, needle string }{"Authorization: " + scheme + secret + ", Basic " + secret, secret})
		}
		for _, scheme := range []string{"Basic ", "'Quoted' ", "`Wrapped` ", "Scheme!#$%&'*+-.^_`|~\t"} {
			inputs = append(inputs, struct{ text, needle string }{"Authorization: Token [REDACTED], " + scheme + secret, secret})
		}
		for _, prefix := range []string{"[]", "[abc]", ",", ")", "[REDACTED]]", "[REDACTED][REDACTED]"} {
			inputs = append(inputs, struct{ text, needle string }{"password=" + prefix + secret, secret})
		}
		escaped := `{"password":"` + secret + `"}`
		for range 4 {
			inputs = append(inputs, struct{ text, needle string }{escaped, secret})
			escaped = strconv.Quote(escaped)
		}
		for _, quote := range []string{`\x22`, `\u0022`} {
			inputs = append(inputs, struct{ text, needle string }{"{" + quote + "password" + quote + ":" + quote + secret + quote + "}", secret})
		}
		for _, form := range []string{`[]interface {}{"%s"}`, `map[string]string{"access":"%s"}`, `sql.NullString{String:"%s", Valid:true}`, `main.Password("%s")`, `main.Password_Value("%s")`, `main.秘密("%s")`, `struct { Raw string }{Raw:"%s"}`, `[]struct { Raw string }{struct { Raw string }{Raw:"%s"}}`, `head %s tail`} {
			inputs = append(inputs,
				struct{ text, needle string }{"{Password:" + fmt.Sprintf(form, secret) + "}", secret},
				struct{ text, needle string }{"{Authorization:" + fmt.Sprintf(form, secret) + "}", secret},
			)
		}
		byteLiteral := fmt.Sprintf("%#v", []byte(secret))
		inputs = append(inputs, struct{ text, needle string }{"{Password:" + byteLiteral + "}", byteLiteral[strings.IndexByte(byteLiteral, '{')+1 : len(byteLiteral)-1]})
		for i, input := range inputs {
			grpcCases = append(grpcCases, []string{input.text, input.needle, "detail", input.text})
			t.Run(fmt.Sprintf("text/%d/%d", n, i), func(t *testing.T) {
				t.Parallel()
				checkBoundaryHooks(t, input.text, input.needle, "detail", input.text)
			})
		}
		for _, key := range []string{"SECRET_KEY", "POSTGRES_PASSWORD", "MYSQL_PASSWORD", "GITHUB_TOKEN", "AWS_SESSION_TOKEN", "X-Auth-Token", "X-Goog-Api-Key", "spring.datasource.password", "service.credential", "client_auth"} {
			grpcCases = append(grpcCases, []string{key + "=" + secret, secret, key, secret})
			t.Run(fmt.Sprintf("key/%d/%s", n, key), func(t *testing.T) { t.Parallel(); checkBoundaryHooks(t, key+"="+secret, secret, key, secret) })
		}
	}
	checkGRPCBoundaryHooks(t, grpcCases)
}

func checkBoundaryHooks(t *testing.T, text, needle, key, value string) {
	t.Helper()
	scanner := embargo.NewScanner()
	check := func(name string, data []byte) {
		t.Helper()
		if len(data) == 0 || bytes.Contains(data, []byte(needle)) || bytes.Contains(data, []byte(strconv.Quote(needle)[1:len(strconv.Quote(needle))-1])) {
			t.Errorf("%s retained fixture: %s", name, data)
		}
	}
	// Attributes and message are independently scanned by each logging wrapper.
	for _, name := range []string{loggerSlog, loggerZap, loggerZerolog, loggerLogrus} {
		check(name+" attribute", loggerOutput(t, scanner, name, key, value))
	}
	var out bytes.Buffer
	slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), scanner)).Info(text)
	check("slog message", out.Bytes())
	out.Reset()
	sink := embargozap.NewWriteSyncer(zapcore.AddSync(&out), scanner)
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{MessageKey: "msg"}), sink, zap.InfoLevel))
	logger.Info(text)
	if err := logger.Sync(); err != nil {
		t.Fatal(err)
	}
	check("zap message", out.Bytes())
	out.Reset()
	writer := embargozerolog.NewWriter(&out, scanner)
	zero := zerolog.New(writer)
	zero.Info().Msg(text)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	check("zerolog message", out.Bytes())
	out.Reset()
	log := logrus.New()
	log.SetOutput(&out)
	log.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{}, scanner))
	log.Info(text)
	check("logrus message", out.Bytes())
	out.Reset()
	event := &sentry.Event{Message: text, Exception: []sentry.Exception{{Value: text}}}
	event.Contexts = map[string]sentry.Context{"extra": {key: value}}
	event = embargosentry.NewBeforeSend(scanner)(event, nil)
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	check("Sentry", encoded)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(embargootel.NewLogExporter(&sdkLogCapture{writer: &out}, scanner))))
	var record otellog.Record
	record.SetBody(attribute.StringValue(text))
	record.AddAttributes(attribute.String(key, value))
	provider.Logger("boundary").Emit(t.Context(), record)
	if shutdownErr := provider.Shutdown(t.Context()); shutdownErr != nil {
		t.Fatal(shutdownErr)
	}
	check("OTel log", out.Bytes())
	out.Reset()
	spans := tracetest.NewInMemoryExporter()
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSyncer(embargootel.NewSpanExporter(spans, scanner)))
	_, span := tracer.Tracer("boundary").Start(t.Context(), text)
	span.SetAttributes(attribute.String(key, value))
	span.AddEvent(text)
	span.End()
	encoded, err = json.Marshal(spans.GetSpans())
	if err != nil {
		t.Fatal(err)
	}
	check("OTel span", encoded)
	if err := tracer.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != text {
			t.Error("HTTP wire body changed")
		}
		w.Header().Set("X-Debug", text)
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.com/?"+url.QueryEscape(key)+"="+url.QueryEscape(value), strings.NewReader(text))
	req.Header.Set(key, value)
	embargo.NewHTTPHandler(next, slog.New(slog.NewJSONHandler(&out, nil)), scanner).ServeHTTP(httptest.NewRecorder(), req)
	check("HTTP request/response headers and query", out.Bytes())
	out.Reset()
}

// Build the same case matrix against the gRPC module in a temporary consumer.
// Its upstream transitive versions stay out of the tests module's manifest.
func checkGRPCBoundaryHooks(t *testing.T, rows [][]string) {
	t.Helper()
	versionCommand := exec.CommandContext(t.Context(), "go", "list", "-m", "-f", "{{.Version}}", "github.com/nao1215/embargo")
	version, err := versionCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	module := fmt.Sprintf("module grpchooks\n\ngo 1.26.11\nrequire (\ngithub.com/nao1215/embargo %s\ngithub.com/nao1215/embargo/adapters/grpc %s\n)\nreplace github.com/nao1215/embargo => %q\nreplace github.com/nao1215/embargo/adapters/grpc => %q\n", strings.TrimSpace(string(version)), strings.TrimSpace(string(version)), filepath.ToSlash(root), filepath.ToSlash(filepath.Join(root, "adapters", "grpc")))
	if writeErr := os.WriteFile(filepath.Join(directory, "go.mod"), []byte(module), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	//nolint:errchkjson // Keep serialization failure explicit if the case shape changes.
	input, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- Execute only the fixed repository fixture in an isolated consumer.
	command := exec.CommandContext(t.Context(), "go", "run", "-mod=mod", filepath.Join(root, "adapters", "grpc", "testdata", "grpchooks", "main.go"))
	command.Dir = directory
	command.Env = append(os.Environ(), "GOWORK=off")
	command.Stdin = bytes.NewReader(input)
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	output, err := command.Output()
	if err != nil {
		t.Fatalf("gRPC boundary gate: %v\n%s", err, diagnostic.String())
	}
	if string(output) != fmt.Sprintf("checked %d unary and %d stream cases\n", len(rows), len(rows)) {
		t.Fatal("gRPC case matrix was not completely exercised")
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestLoggerIntegerExpansionFailureIsWithheld(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner()
	input := json.RawMessage(`{"email":"alice@example.com","public":1e1048576}`)
	if out, err := scanner.MaskJSON(input); err == nil || out != nil {
		t.Fatal("fixture must fail integer expansion")
	}
	for _, name := range []string{loggerSlog, loggerZap, loggerZerolog, loggerLogrus} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := loggerOutput(t, scanner, name, "payload", input)
			var fields map[string]any
			if err := json.Unmarshal(out, &fields); err != nil {
				t.Fatal(err)
			}
			messageKey := slog.MessageKey
			if name == loggerZerolog {
				messageKey = metamorphicMessageKey
			}
			if fields[messageKey] != "embargo: record withheld (size limit)" || fields["withheld_attributes"] == nil {
				t.Fatalf("missing size diagnostic: %s", out)
			}
			for key := range fields {
				if key != "time" && key != "level" && key != messageKey && key != "withheld_attributes" {
					t.Fatalf("original field survived: %s", out)
				}
			}
		})
	}
}

// frameworkJSONCodec lets the Connect example run without generated protobuf
// code; Connect calls it for application/json requests.
type frameworkJSONCodec struct{}

func (frameworkJSONCodec) Name() string { return "json" }

func (frameworkJSONCodec) Marshal(message any) ([]byte, error) { return json.Marshal(message) }

func (frameworkJSONCodec) Unmarshal(data []byte, message any) error {
	return json.Unmarshal(data, message)
}

type frameworkLogin struct {
	Email string `json:"email"`
}

// TestWebFrameworkAccessLogs wraps gin, echo and Connect servers the way
// doc/adapters.md shows: the framework stays an http.Handler behind
// NewHTTPHandler, and application logs go through NewSlogHandler.
func TestWebFrameworkAccessLogs(t *testing.T) {
	t.Parallel()
	const apiKey = "sk-proj-" + "Fake0Fake0Fake0Fake0Fake0Fake0"
	gin.SetMode(gin.ReleaseMode)
	frameworks := map[string]func(*slog.Logger) http.Handler{
		"gin": func(logger *slog.Logger) http.Handler {
			router := gin.New()
			router.GET("/login", func(c *gin.Context) {
				logger.Info("login", "email", c.Query("email"))
				c.Status(http.StatusNoContent)
			})
			return router
		},
		"echo": func(logger *slog.Logger) http.Handler {
			server := echo.New()
			server.GET("/login", func(c *echo.Context) error {
				logger.Info("login", "email", c.QueryParam("email"))
				return c.NoContent(http.StatusNoContent)
			})
			return server
		},
		"connect": func(logger *slog.Logger) http.Handler {
			mux := http.NewServeMux()
			mux.Handle("/login", connect.NewUnaryHandler("/login", func(_ context.Context, request *connect.Request[frameworkLogin]) (*connect.Response[frameworkLogin], error) {
				logger.Info("login", "email", request.Msg.Email)
				return connect.NewResponse(&frameworkLogin{Email: ""}), nil
			}, connect.WithCodec(frameworkJSONCodec{})))
			return mux
		},
	}
	for name, build := range frameworks {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			scanner := embargo.NewScanner()
			logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), scanner))
			handler := embargo.NewHTTPHandler(build(logger), logger, scanner)
			target := "/login?email=alice%40example.com&token=" + apiKey
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			if name == "connect" {
				request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login?token="+apiKey, strings.NewReader(`{"email":"alice@example.com"}`))
				request.Header.Set("Content-Type", "application/json")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code >= http.StatusBadRequest {
				t.Fatalf("status %d: %s", response.Code, response.Body.String())
			}
			logs := out.String()
			if strings.Count(logs, "\n") != 2 || strings.Contains(logs, "alice@example.com") || strings.Contains(logs, apiKey) || !strings.Contains(logs, `"target":"/login?`) {
				t.Fatalf("framework logs:\n%s", logs)
			}
		})
	}
}
