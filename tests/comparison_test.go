package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	dlp "github.com/bytedance/godlp"
	"github.com/bytedance/godlp/dlpheader"
	masker "github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/httpmask"
	"github.com/icntswm/go-masker/slogmask"
	"github.com/icntswm/go-masker/zapmask"
	"github.com/icntswm/go-masker/zerologmask"
	"github.com/m-mizutani/masq"
	"github.com/rs/zerolog"
	slogformatter "github.com/samber/slog-formatter"
	mask "github.com/showa-93/go-mask"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nao1215/embargo"
	embargozap "github.com/nao1215/embargo/adapters/zap"
	"github.com/nao1215/embargo/embargotest"
)

const (
	comparisonFlat           = "flat"
	comparisonDLPName        = "godlp"
	comparisonFormatterName  = "slog-formatter"
	comparisonCopyName       = "go-mask"
	comparisonNested         = "nested"
	comparisonLarge          = "large50"
	comparisonPasswordKey    = "password"
	comparisonID             = "u123"
	comparisonOpaque         = "opaque-value"
	comparisonEmailKey       = "email"
	comparisonClean          = "clean"
	comparisonEmail          = "alice@example.com"
	comparisonMaskerName     = "go-masker"
	comparisonMasqName       = "masq"
	comparisonEmbargoName    = "embargo"
	comparisonMap            = "map"
	comparisonPassword       = "opaque-password"
	comparisonRecovery       = "opaque-recovery"
	comparisonMaskedPassword = `"Password":"[REDACTED]"`
)

type comparisonJSON struct{}

func (comparisonJSON) MarshalJSON() ([]byte, error) {
	return []byte(`{"email":"alice@example.com"}`), nil
}

type comparisonUser struct {
	ID       string
	Email    string
	Password string
	Recovery string `masq:"secret"`
	Count    int
}

func comparisonScanner() *embargo.Scanner {
	return embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN), embargo.WithMinConfidence(0.7), embargo.WithSensitiveKeys(comparisonPasswordKey, "passwd", "secret", "token", "api_key", "authorization", "cookie", "set-cookie", "recovery"))
}

func comparisonMasq() func([]string, slog.Attr) slog.Attr {
	return masq.New(masq.WithAllowedType(reflect.TypeFor[time.Time](), reflect.TypeFor[slog.Level]()), masq.WithRegex(regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)), masq.WithRegex(regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)), masq.WithFieldName("Password"), masq.WithFieldName(comparisonPasswordKey), masq.WithFieldName("token"), masq.WithTag("secret"))
}

func comparisonHandler(mode string, out io.Writer) slog.Handler {
	options := &slog.HandlerOptions{}
	if mode == comparisonMaskerName {
		options.ReplaceAttr = slogmask.ReplaceAttr(comparisonValueMasker())
	}
	if mode == comparisonMasqName {
		options.ReplaceAttr = comparisonMasq()
	}
	h := slog.NewJSONHandler(out, options)
	if mode == comparisonEmbargoName {
		return embargo.NewSlogHandler(h, comparisonScanner())
	}
	return h
}

type comparisonCase struct {
	name                  string
	emit                  func(*slog.Logger)
	wantMasq, wantEmbargo string
}

func comparisonCases() []comparisonCase {
	return []comparisonCase{
		{"nested_struct", func(l *slog.Logger) {
			l.Info("request", "user", struct{ ID, Email string }{comparisonID, comparisonEmail})
		}, `"user":{"ID":"u123","Email":"[REDACTED]"}`, `"user":{"ID":"u123","Email":"[REDACTED]"}`},
		{"message", func(l *slog.Logger) { l.Info("login failed for alice@example.com") }, `"msg":"[REDACTED]"`, `"msg":"login failed for [REDACTED]"`},
		{"attribute_key", func(l *slog.Logger) { l.Info("request", comparisonEmail, "ok") }, `"alice@example.com":"ok"`, `"[REDACTED]":"ok"`},
		{"group_name", func(l *slog.Logger) { l.WithGroup(comparisonEmail).Info("request", "status", "ok") }, `"alice@example.com":{"status":"ok"}`, `"[REDACTED]":{"status":"ok"}`},
		{"marshal_json", func(l *slog.Logger) { l.Info("request", "data", comparisonJSON{}) }, `"email":"alice@example.com"`, `"email":"[REDACTED]"`},
		{"wrapped_error", func(l *slog.Logger) {
			l.Info("request", "error", fmt.Errorf("request failed: %w", errors.New(comparisonEmail)))
		}, `"error":"[REDACTED]"`, `"error":"request failed: [REDACTED]"`},
		{"opaque_password", func(l *slog.Logger) { l.Info("request", "data", struct{ Password string }{comparisonOpaque}) }, comparisonMaskedPassword, comparisonMaskedPassword},
		{"secret_wrapper", func(l *slog.Logger) {
			l.Info("request", "data", struct{ Password embargo.Secret[string] }{embargo.NewSecret(comparisonOpaque)})
		}, comparisonMaskedPassword, comparisonMaskedPassword},
		// #nosec G101 -- Public synthetic recovery field used only to test redaction.
		{"tag_or_key", func(l *slog.Logger) {
			l.Info("request", "user", comparisonUser{ID: comparisonID, Recovery: comparisonOpaque})
		}, `"Recovery":"[REDACTED]"`, `"Recovery":"[REDACTED]"`},
		{"valid_card", func(l *slog.Logger) { l.Info("request", "card", "4111111111111111") }, `"card":"[REDACTED]"`, `"card":"[REDACTED]"`},
		{"invalid_luhn", func(l *slog.Logger) { l.Info("request", "order", "4111111111111112") }, `"order":"[REDACTED]"`, `"order":"4111111111111112"`},
		{comparisonMap, func(l *slog.Logger) {
			l.Info("request", "data", map[string]any{comparisonPasswordKey: comparisonOpaque, comparisonEmailKey: comparisonEmail, "count": 17})
		}, `"data":{"count":17,"email":null,"password":null}`, `"data":{"count":17,"email":"[REDACTED]","password":"[REDACTED]"}`},
	}
}

func TestComparisonCorrectness(t *testing.T) {
	t.Parallel()
	var table strings.Builder
	writeComparisonTable(t, &table, "| Case | masq v0.2.3 output fragment | embargo output fragment |\n|---|---|---|\n")
	for _, tc := range comparisonCases() {
		for _, mode := range []string{comparisonMasqName, comparisonEmbargoName} {
			var out bytes.Buffer
			tc.emit(slog.New(comparisonHandler(mode, &out)))
			want := tc.wantMasq
			if mode == comparisonEmbargoName {
				want = tc.wantEmbargo
			}
			if !json.Valid(bytes.TrimSpace(out.Bytes())) || !strings.Contains(out.String(), want) {
				t.Errorf("%s/%s: %s; want %s", tc.name, mode, out.String(), want)
			}
			if mode == comparisonEmbargoName && strings.Contains(out.String(), comparisonOpaque) {
				t.Errorf("%s/%s: raw sensitive fixture remains in output", tc.name, mode)
			}
		}
		writeComparisonTable(t, &table, "| %s | `%s` | `%s` |\n", tc.name, tc.wantMasq, tc.wantEmbargo)
	}
	path := "../doc/comparison-correctness.md"
	if os.Getenv("UPDATE_DOCS") == "1" {
		if err := os.WriteFile(path, []byte(table.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != table.String() {
		t.Fatal("run make comparison-doc to update correctness table")
	}
}

func comparisonEvents() map[string][]slog.Attr {
	events := map[string][]slog.Attr{
		comparisonFlat:   {slog.String(comparisonEmailKey, comparisonEmail), slog.String("card", "4111111111111111")},
		comparisonNested: {slog.Any("user", comparisonUser{comparisonID, comparisonEmail, comparisonPassword, comparisonRecovery, 17})},
		comparisonMap:    {slog.Any("data", map[string]any{comparisonEmailKey: comparisonEmail, "card": "4111111111111111", comparisonPasswordKey: comparisonPassword, "count": 17})},
		comparisonClean:  {slog.String("status", "accepted"), slog.Int("count", 17), slog.Bool("ok", true)},
	}
	large := make([]slog.Attr, 0, 50)
	for i := range 48 {
		large = append(large, slog.String(fmt.Sprintf("field%d", i), "clean application value"))
	}
	events[comparisonLarge] = append(large, events[comparisonFlat]...)
	return events
}

func BenchmarkComparison(b *testing.B) {
	events := comparisonEvents()
	for _, name := range []string{comparisonFlat, comparisonNested, comparisonMap, comparisonClean, comparisonLarge} {
		attrs := events[name]
		b.Run(name, func(b *testing.B) {
			for _, mode := range []string{scenarioPlain, comparisonMasqName, comparisonEmbargoName, comparisonMaskerName} {
				b.Run(mode, func(b *testing.B) {
					logger := slog.New(comparisonHandler(mode, io.Discard))
					ctx := context.Background()
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						logger.LogAttrs(ctx, slog.LevelInfo, "request", attrs...)
					}
				})
			}
		})
	}
}

func BenchmarkStructuredPath(b *testing.B) {
	scanner := comparisonScanner()
	value := comparisonUser{comparisonID, comparisonEmail, comparisonPassword, comparisonRecovery, 17}
	for _, mode := range []string{"old_string", "json_shape"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				// #nosec G117 -- Encode synthetic secrets to measure masking, never publish the raw document.
				//nolint:musttag // Native exported field names are part of the comparison.
				encoded, err := json.Marshal(value)
				if err != nil {
					b.Fatal(err)
				}
				if mode == "old_string" {
					_ = embargo.Mask(string(encoded), scanner.Scan(encoded))
				} else {
					if _, err := scanner.MaskJSON(encoded); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func writeComparisonTable(t *testing.T, builder *strings.Builder, format string, args ...any) {
	t.Helper()
	if _, err := fmt.Fprintf(builder, format, args...); err != nil {
		t.Fatal(err)
	}
}

func TestMasqRequiresDetectionRules(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: masq.New()}))
	logger.Info("request", "email", comparisonEmail, "card", "4111111111111111")
	if !strings.Contains(out.String(), comparisonEmail) || !strings.Contains(out.String(), "4111111111111111") {
		t.Fatal("review default masq behavior before changing the comparison claim")
	}
}

func formatterHandler(out io.Writer) slog.Handler {
	return slogformatter.NewFormatterHandler(slogformatter.PIIFormatter(comparisonEmailKey), slogformatter.PIIFormatter("card"), slogformatter.PIIFormatter("user"), slogformatter.PIIFormatter("data"), slogformatter.PIIFormatter(comparisonPasswordKey), slogformatter.PIIFormatter("token"))(slog.NewJSONHandler(out, nil))
}

func comparisonMasker() *mask.Masker {
	m := mask.NewMasker()
	m.RegisterMaskStringFunc(mask.MaskTypeFixed, m.MaskFixedString)
	for _, field := range []string{"Email", "Password", "Recovery", comparisonEmailKey, comparisonPasswordKey, "card"} {
		m.RegisterMaskField(field, mask.MaskTypeFixed)
	}
	return m
}

func godlpEngine(tb testing.TB) dlpheader.EngineAPI {
	tb.Helper()
	engine, err := dlp.NewEngine("embargo-comparison")
	if err != nil {
		tb.Fatal(err)
	}
	// Select the documented built-in email, credit card, IP and phone rules.
	config := strings.Replace(engine.GetDefaultConf(), "EnableRules: []", "EnableRules: [1, 2, 6, 16, 20, 35]", 1)
	if err := engine.ApplyConfig(config); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(engine.Close)
	return engine
}

//nolint:paralleltest // godlp configuration writes package globals.
func TestComparisonOtherLibraries(t *testing.T) {
	// godlp initializes package globals; keep its setup out of parallel tests.
	engine := godlpEngine(t)
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN, embargo.KindJPPhone, embargo.KindIPAddr), embargo.WithMinConfidence(0.7))
	var table strings.Builder
	var details strings.Builder
	writeComparisonTable(t, &table, "| Text fixture | godlp v1.2.15 | godlp findings | embargo | embargo findings |\n|---|---|---:|---|---:|\n")
	for _, text := range []string{"email alice@example.com", "credit card 4111111111111111", "IP 192.0.2.1", "phone 03-1234-5678", "phone 202-555-0123", "credit card 4111111111111112"} {
		safe, found, err := engine.Deidentify(text)
		if err != nil {
			t.Fatal(err)
		}
		ours := embargo.Mask(text, scanner.ScanString(text))
		writeComparisonTable(t, &table, "| `%s` | `%s` | %d | `%s` | %d |\n", text, safe, len(found), ours, len(scanner.ScanString(text)))
	}
	writeComparisonTable(t, &table, "\n| Shared event | slog-formatter v1.3.0 PIIFormatter | go-mask v0.6.2 field rules |\n|---|---|---|\n")
	events := comparisonEvents()
	for _, name := range []string{comparisonFlat, comparisonNested, comparisonMap, comparisonClean, comparisonLarge} {
		attrs := events[name]
		var out bytes.Buffer
		slog.New(formatterHandler(&out)).LogAttrs(t.Context(), slog.LevelInfo, "request", attrs...)
		var got map[string]json.RawMessage
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		delete(got, "time")
		delete(got, "level")
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		payload := map[string]any{}
		for _, attr := range attrs {
			payload[attr.Key] = attr.Value.Any()
		}
		safe, err := comparisonMasker().Mask(payload)
		if err != nil {
			t.Fatal(err)
		}
		masked, err := json.Marshal(safe)
		if err != nil {
			t.Fatal(err)
		}
		// Keep long output outside table cells so the diff stays readable.
		if len(encoded) > 120 || len(masked) > 120 {
			writeComparisonTable(t, &table, "| %s | [Full formatter output](#%s-output) | [Full copy output](#%s-output) |\n", name, name, name)
			writeComparisonTable(t, &details, "\n### %s output\n\nFormatter:\n\n```json\n%s\n```\n\nCopy:\n\n```json\n%s\n```\n", name, encoded, masked)
		} else {
			writeComparisonTable(t, &table, "| %s | `%s` | `%s` |\n", name, encoded, masked)
		}
	}
	writeComparisonTable(t, &table, "%s", details.String())
	path := "../doc/comparison-libraries.md"
	if os.Getenv("UPDATE_DOCS") == "1" {
		if err := os.WriteFile(path, []byte(table.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != table.String() {
		t.Fatal("run make comparison-doc to update library outputs")
	}
}

func BenchmarkComparisonFormatter(b *testing.B) {
	events := comparisonEvents()
	for _, name := range []string{comparisonFlat, comparisonNested, comparisonMap, comparisonClean, comparisonLarge} {
		attrs := events[name]
		b.Run(name, func(b *testing.B) {
			logger := slog.New(formatterHandler(io.Discard))
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				logger.LogAttrs(ctx, slog.LevelInfo, "request", attrs...)
			}
		})
	}
}

func BenchmarkComparisonText(b *testing.B) {
	engine := godlpEngine(b)
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN, embargo.KindIPAddr, embargo.KindJPPhone), embargo.WithMinConfidence(0.7))
	text := "email alice@example.com; credit card 4111111111111111; IP 192.0.2.1; phone 03-1234-5678"
	b.Run(comparisonDLPName, func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, _, err := engine.Deidentify(text); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run(comparisonEmbargoName, func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = embargo.Mask(text, scanner.ScanString(text))
		}
	})
}

func BenchmarkComparisonStruct(b *testing.B) {
	value := comparisonUser{comparisonID, comparisonEmail, comparisonPassword, comparisonRecovery, 17}
	copyMasker := comparisonMasker()
	scanner := comparisonScanner()
	b.Run("go_mask", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			safe, err := copyMasker.Mask(value)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := json.Marshal(safe); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run(comparisonEmbargoName, func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			// #nosec G117 -- The benchmark deliberately encodes synthetic fields before masking them.
			//nolint:musttag // Native exported field names are part of the comparison.
			data, err := json.Marshal(value)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := scanner.MaskJSON(data); err != nil {
				b.Fatal(err)
			}
		}
	})
}

type comparisonObservation struct {
	testing.TB

	failed bool
}

func (p *comparisonObservation) Error(...any) { p.failed = true }

func TestExistingMaskerOutputCheck(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"plain", comparisonMasqName} {
		for _, fixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fixed=%v", mode, fixed), func(t *testing.T) {
				t.Parallel()
				observation := &comparisonObservation{TB: t}
				scanner := comparisonScanner()
				recorder := embargotest.New(observation, embargotest.WithScanner(scanner))
				handler := comparisonHandler(mode, recorder.Writer("logs"))
				if fixed {
					handler = embargo.NewSlogHandler(handler, scanner)
				}
				// A real application event whose key is outside masq's value traversal.
				slog.New(handler).Info("request", comparisonEmail, "accepted", comparisonPasswordKey, "opaque")
				recorder.Expect("logs", func(data []byte) bool {
					// Existing Expect accepts any predicate: enforce this scanner's key rules.
					safe, err := scanner.MaskJSON(data)
					var compact bytes.Buffer
					return err == nil && json.Compact(&compact, data) == nil && bytes.Equal(safe, compact.Bytes())
				})
				if got := recorder.Check(); got != fixed || observation.failed == fixed {
					t.Fatalf("Check=%v, fixed=%v, failure=%v", got, fixed, observation.failed)
				}
			})
		}
	}
}

func TestComparisonDocuments(t *testing.T) {
	t.Parallel()
	document, err := os.ReadFile("../doc/comparison.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"comparison", "correctness"} {
		start, end := "<!-- "+name+":start -->", "<!-- "+name+":end -->"
		text := string(document)
		if strings.Count(text, start) != 1 || strings.Count(text, end) != 1 || strings.Index(text, start) >= strings.Index(text, end) {
			t.Fatalf("missing, repeated or reversed %s markers", name)
		}
	}
	command := exec.CommandContext(t.Context(), "python3", "scripts/comparison_docs.py", "--check")
	command.Dir = ".."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("comparison artifacts: %v\n%s", err, output)
	}
}

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
	case comparisonMaskerName:
		handler = comparisonHandler(comparisonMaskerName, out)
	case comparisonDLPName:
		handler = catchHandler(t, mode, out, godlpEngine(t))
	case comparisonMasqName:
		handler = slog.NewJSONHandler(out, &slog.HandlerOptions{ReplaceAttr: comparisonMasq()})
	case comparisonFormatterName:
		handler = slogformatter.NewFormatterHandler(slogformatter.FormatByKey("password", func(slog.Value) slog.Value { return slog.StringValue("[REDACTED]") }), slogformatter.FormatByKey(scenarioTokenKey, func(slog.Value) slog.Value { return slog.StringValue("[REDACTED]") }))(handler)
	}
	logger := slog.New(handler)
	return func(message string, attrs ...slog.Attr) {
		if mode == comparisonCopyName {
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

//nolint:paralleltest // The shared scenarios also initialize godlp's package globals.
func TestLeakScenarios(t *testing.T) {
	modes := []string{scenarioSlog, scenarioZap, comparisonMasqName, comparisonFormatterName, comparisonCopyName, comparisonMaskerName, comparisonDLPName}
	var table strings.Builder
	writeComparisonTable(t, &table, "| Service output | embargo slog | embargo zap | masq v0.2.3 | slog-formatter v1.3.0 | go-mask v0.6.2 | go-masker v0.6.1 | godlp v1.2.15 |\n|---|---|---|---|---|---|---|---|\n")
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

func comparisonValueMasker() *masker.Masker {
	core, err := masker.New(masker.DefaultPolicy(), masker.WithCardNumberDetection(), masker.WithPreserveSafeTypes(), masker.WithTagRule("fixed", masker.FullRule()))
	if err != nil {
		panic(err)
	}
	return core
}

type comparisonTagged struct {
	Value string `masq:"secret" mask:"fixed"`
}
type catchScenario struct {
	emit                func(*slog.Logger)
	name, label, needle string
	positive            bool
}

func catchScenarios() []catchScenario {
	return []catchScenario{
		{name: "message_email", label: "Email in message", needle: comparisonEmail, emit: func(l *slog.Logger) { l.Info("login " + comparisonEmail) }, positive: true},
		{name: "nested_email", label: "Nested email", needle: comparisonEmail, emit: func(l *slog.Logger) { l.Info("event", "user", struct{ Email string }{comparisonEmail}) }, positive: true},
		{name: "attribute_key", label: "Email in attribute key", needle: comparisonEmail, emit: func(l *slog.Logger) { l.Info("event", comparisonEmail, "ok") }, positive: true},
		{name: "group_name", label: "Email in group name", needle: comparisonEmail, emit: func(l *slog.Logger) { l.WithGroup(comparisonEmail).Info("event", "status", "ok") }, positive: true},
		{name: "marshal_json", label: "Custom JSON email", needle: comparisonEmail, emit: func(l *slog.Logger) { l.Info("event", "data", comparisonJSON{}) }, positive: true},
		{name: "opaque_password", label: "Named password", needle: comparisonOpaque, emit: func(l *slog.Logger) { l.Info("event", "password", comparisonOpaque) }, positive: true},
		{name: "tag_only", label: "Opaque value: tag only", needle: comparisonOpaque, emit: func(l *slog.Logger) { l.Info("event", "payload", comparisonTagged{comparisonOpaque}) }, positive: true},
		{name: "valid_card", label: "Valid card in text", needle: "4111111111111111", emit: func(l *slog.Logger) { l.Info("charge 4111111111111111") }, positive: true},
		{name: "labeled_card", label: "Card with credit card label", needle: "4111111111111111", emit: func(l *slog.Logger) { l.Info("credit card 4111111111111111") }, positive: true},
		{name: "embedded_json", label: "JSON inside a string", needle: comparisonOpaque, emit: func(l *slog.Logger) { l.Info("event", "detail", `{"token":"opaque-value"}`) }, positive: true},
		{name: "bearer", label: "Bearer in message", needle: comparisonOpaque, emit: func(l *slog.Logger) { l.Info("Authorization: Bearer " + comparisonOpaque) }, positive: true},
		{name: "japanese_phone", label: "Japanese phone", needle: "03-1234-5678", emit: func(l *slog.Logger) { l.Info("contact 03-1234-5678") }, positive: true},
		{name: "us_phone", label: "US phone", needle: "202-555-0123", emit: func(l *slog.Logger) { l.Info("contact 202-555-0123") }, positive: true},
		{name: "invalid_luhn", label: "Invalid card control", needle: "4111111111111112", emit: func(l *slog.Logger) { l.Info("order 4111111111111112") }, positive: false},
		{name: "clean_reference", label: "Clean reference control", needle: "job-R7", emit: func(l *slog.Logger) { l.Info("completed job-R7") }, positive: false},
	}
}

type catchObservation struct {
	Output  string `json:"output"`
	Removed bool   `json:"removed"`
}
type catchRow struct {
	Results  map[string]catchObservation `json:"results"`
	Name     string                      `json:"name"`
	Label    string                      `json:"label"`
	Positive bool                        `json:"positive"`
}
type catchReport struct {
	Versions map[string]string `json:"versions"`
	Rows     []catchRow        `json:"rows"`
}

func catchHandler(t *testing.T, mode string, out io.Writer, engine dlpheader.EngineAPI) slog.Handler {
	t.Helper()
	switch mode {
	case comparisonEmbargoName:
		return embargo.NewSlogHandler(slog.NewJSONHandler(out, nil), embargo.NewScanner(embargo.WithMinConfidence(0.7)))
	case comparisonMasqName, comparisonMaskerName:
		return comparisonHandler(mode, out)
	case comparisonFormatterName:
		return formatterHandler(out)
	}
	copyMasker := comparisonMasker()
	return slog.NewJSONHandler(out, &slog.HandlerOptions{ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
		if attr.Key == slog.TimeKey || attr.Key == slog.LevelKey {
			return attr
		}
		value := attr.Value.Any()
		if mode == comparisonCopyName {
			safe, err := copyMasker.Mask(map[string]any{attr.Key: value})
			if err != nil {
				t.Fatal(err)
			}
			fields, ok := safe.(map[string]any)
			if !ok {
				t.Fatal("copy masker changed object type")
			}
			return slog.Any(attr.Key, fields[attr.Key])
		}
		if err, ok := value.(error); ok {
			value = err.Error()
		}
		if text, ok := value.(string); ok {
			safe, _, err := engine.Deidentify(text)
			if err != nil {
				t.Fatal(err)
			}
			return slog.String(attr.Key, safe)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		safe, _, err := engine.Deidentify(string(encoded))
		if err != nil || !json.Valid([]byte(safe)) {
			t.Fatal("invalid masked JSON", err)
		}
		return slog.Any(attr.Key, json.RawMessage(safe))
	}})
}

//nolint:paralleltest // godlp initializes package globals; use the same serial setup as its other probes.
func TestComparisonScenarios(t *testing.T) {
	engine := godlpEngine(t)
	report := catchReport{Versions: map[string]string{"embargo": "working source", "masq": "v0.2.3", comparisonFormatterName: "v1.3.0", comparisonCopyName: "v0.6.2", comparisonDLPName: "v1.2.15", "go-masker": "v0.6.1"}}
	for _, scenario := range catchScenarios() {
		row := catchRow{Name: scenario.name, Label: scenario.label, Positive: scenario.positive, Results: map[string]catchObservation{}}
		for _, mode := range []string{comparisonEmbargoName, comparisonMasqName, comparisonMaskerName, comparisonFormatterName, comparisonCopyName, comparisonDLPName} {
			var out bytes.Buffer
			scenario.emit(slog.New(catchHandler(t, mode, &out, engine)))
			var event map[string]any
			if err := json.Unmarshal(out.Bytes(), &event); err != nil || len(event) == 0 {
				t.Fatal("missing or invalid scenario output", mode, err)
			}
			delete(event, "time")
			data, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			row.Results[mode] = catchObservation{Output: string(data), Removed: !strings.Contains(string(data), scenario.needle)}
		}
		report.Rows = append(report.Rows, row)
	}
	//nolint:errchkjson // Keep output errors explicit if report types evolve.
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := "../doc/comparison-scenarios.json"
	if os.Getenv("UPDATE_DOCS") == "1" {
		if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("comparison scenarios changed: run make comparison-doc", err)
	}
}

func TestComparisonMaskerAdapters(t *testing.T) {
	t.Parallel()
	core := comparisonValueMasker()
	for _, mode := range []string{"slog", "zap", "zerolog"} {
		var out bytes.Buffer
		switch mode {
		case "slog":
			slog.New(comparisonHandler(comparisonMaskerName, &out)).Info("event", "token", comparisonOpaque)
		case "zap":
			zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapmask.NewWriteSyncer(&out, core), zap.InfoLevel)).Info("event", zap.String("token", comparisonOpaque))
		case "zerolog":
			logger := zerolog.New(zerologmask.NewWriter(&out, core))
			logger.Info().Str("token", comparisonOpaque).Msg("event")
		}
		if !json.Valid(out.Bytes()) || strings.Contains(out.String(), comparisonOpaque) || !strings.Contains(out.String(), referenceMarker) {
			t.Fatal(mode, "adapter did not mask", out.String())
		}
	}
	adapter, err := httpmask.New(core)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := adapter.Headers(http.Header{"Authorization": {"Bearer " + comparisonOpaque}})
	if err != nil || strings.Contains(fmt.Sprint(headers), comparisonOpaque) {
		t.Fatal("HTTP header leak", err)
	}
	target, err := adapter.URLString("https://example.net/?token=" + comparisonOpaque)
	if err != nil || strings.Contains(target, comparisonOpaque) {
		t.Fatal("HTTP URL leak", err)
	}
}

func TestComparisonTypedCopy(t *testing.T) {
	t.Parallel()
	original := comparisonUser{ID: comparisonID, Email: comparisonEmail, Password: comparisonOpaque}
	masked, err := comparisonMasker().Mask(original)
	copyOf, ok := masked.(comparisonUser)
	if err != nil || !ok || copyOf.ID != original.ID || copyOf.Email == original.Email || copyOf.Password == original.Password || original.Password != comparisonOpaque {
		t.Fatal("typed copy contract changed", err)
	}
}
