package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/m-mizutani/masq"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

const (
	caseKeys   = "key denylist"
	caseManual = "manual redact"
	caseTags   = "masq tags"
	casePAN    = "4111111111111111"
	caseOpaque = "pretend-upstream-secret-abcdefxyz"
	caseOrder  = "order-AQZ"
	caseMasked = "masked"
	caseMissed = "missed"
)

type adoptionCase struct {
	emit    func(*testing.T, *slog.Logger, io.Writer)
	name    string
	canary  string
	exposed []string
}

type adoptionProfile struct {
	Password string `masq:"secret"`
	Card     string
}

func adoptionCases() []adoptionCase {
	token := "ghp_" + strings.Repeat("aB3x", 9)
	return []adoptionCase{
		{name: "added struct field", canary: casePAN, exposed: []string{casePAN}, emit: func(_ *testing.T, l *slog.Logger, _ io.Writer) {
			l.Info("checkout", "profile", adoptionProfile{Password: caseOpaque, Card: casePAN})
		}},
		{name: "client error", canary: token, exposed: []string{token}, emit: func(_ *testing.T, l *slog.Logger, _ io.Writer) {
			// An upstream client may return response text in its error.
			l.Error("upstream failed", "error", errors.New("remote rejected "+token))
		}},
		{name: "HTTP query", canary: caseOpaque, exposed: []string{caseOpaque}, emit: func(t *testing.T, l *slog.Logger, _ io.Writer) {
			t.Helper()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.test/pay?token="+caseOpaque, nil)
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				l.Info("request", "url", r.URL.String())
				w.WriteHeader(http.StatusNoContent)
			}).ServeHTTP(httptest.NewRecorder(), request)
		}},
		{name: "wrapped error", canary: caseOpaque, exposed: []string{caseOpaque}, emit: func(_ *testing.T, l *slog.Logger, _ io.Writer) {
			err := fmt.Errorf("checkout: %w", fmt.Errorf("connect: %w", errors.New("password="+caseOpaque)))
			l.Error("failed", "error", err)
		}},
		{name: "DSN password", canary: caseOpaque, exposed: []string{caseOpaque}, emit: func(_ *testing.T, l *slog.Logger, _ io.Writer) {
			l.Info("connecting", "dsn", "postgres://reader:"+caseOpaque+"@db.example/orders")
		}},
		{name: "header dump", canary: caseOpaque, exposed: []string{caseOpaque}, emit: func(t *testing.T, l *slog.Logger, _ io.Writer) {
			t.Helper()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.test/pay", nil)
			request.Header.Set("Authorization", "Bearer "+caseOpaque)
			dump, err := httputil.DumpRequest(request, false)
			if err != nil {
				t.Fatal(err)
			}
			l.Info("request", "dump", string(dump))
		}},
		{name: "unwrapped logger", canary: token, exposed: []string{token}, emit: func(_ *testing.T, _ *slog.Logger, out io.Writer) {
			// A separately constructed standard logger bypasses every configured handler.
			log.New(out, "legacy ", 0).Print("upstream rejected " + token)
		}},
		{name: "card last four", canary: casePAN, exposed: []string{casePAN[12:]}, emit: func(_ *testing.T, l *slog.Logger, _ io.Writer) {
			l.Info("checkout", "card_tail", casePAN[12:])
		}},
		{name: "truncated card", canary: casePAN, exposed: []string{casePAN[:8]}, emit: func(_ *testing.T, l *slog.Logger, _ io.Writer) {
			l.Info("checkout", "card_prefix", casePAN[:8])
		}},
		{name: "base64 token", canary: token, exposed: []string{base64.StdEncoding.EncodeToString([]byte(token))}, emit: func(_ *testing.T, l *slog.Logger, _ io.Writer) {
			l.Info("upstream response", "payload", base64.StdEncoding.EncodeToString([]byte(token)))
		}},
		{name: "hex token", canary: token, exposed: []string{hex.EncodeToString([]byte(token))}, emit: func(_ *testing.T, l *slog.Logger, _ io.Writer) {
			l.Info("upstream response", "payload", hex.EncodeToString([]byte(token)))
		}},
		{name: "split token lines", canary: token, exposed: []string{token[:20], token[20:]}, emit: func(_ *testing.T, l *slog.Logger, _ io.Writer) {
			l.Info("chunk one", "payload", token[:20])
			l.Info("chunk two", "payload", token[20:])
		}},
	}
}

func adoptionHandler(mode string, out io.Writer) slog.Handler {
	options := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}
	switch mode {
	case caseTags:
		options.ReplaceAttr = masq.New(masq.WithTag("secret"), masq.WithAllowedType(reflect.TypeFor[time.Time](), reflect.TypeFor[slog.Level]()))
	case caseManual:
		// A team's explicit text policy: cards and password/token assignments.
		pattern := regexp.MustCompile(`\b\d{13,19}\b|(?i:password|token)=[^ &"\\]+`)
		options.ReplaceAttr = func(_ []string, a slog.Attr) slog.Attr {
			if a.Value.Kind() == slog.KindString {
				a.Value = slog.StringValue(pattern.ReplaceAllString(a.Value.String(), "[REDACTED]"))
			}
			if err, ok := a.Value.Any().(error); ok {
				a.Value = slog.StringValue(pattern.ReplaceAllString(err.Error(), "[REDACTED]"))
			}
			return a
		}
	case caseKeys:
		options.ReplaceAttr = masq.New(masq.WithFieldName("Password"), masq.WithFieldName("password"), masq.WithFieldName("token"), masq.WithFieldName("authorization"), masq.WithAllowedType(reflect.TypeFor[time.Time](), reflect.TypeFor[slog.Level]()))
	}
	handler := slog.NewJSONHandler(out, options)
	if mode == comparisonEmbargoName {
		return embargo.NewSlogHandler(handler, embargo.NewScanner())
	}
	return handler
}

func adoptionOutput(t *testing.T, tc adoptionCase, mode string) []byte {
	t.Helper()
	var out bytes.Buffer
	logger := slog.New(adoptionHandler(mode, &out)).With("order_id", caseOrder)
	tc.emit(t, logger, &out)
	// A separate success record requires diagnostic content to survive too.
	logger.Info("request complete")
	if !bytes.Contains(out.Bytes(), []byte(caseOrder)) || !bytes.Contains(out.Bytes(), []byte("request complete")) {
		t.Fatal("diagnostic output lost")
	}
	return out.Bytes()
}

func adoptionVerdict(t *testing.T, tc adoptionCase, data []byte) string {
	t.Helper()
	exposed := false
	for _, fragment := range tc.exposed {
		exposed = exposed || bytes.Contains(data, []byte(fragment))
	}
	probe := &observationTB{TB: t}
	r := embargotest.New(probe, embargotest.WithCanary([]byte(tc.canary)))
	if _, err := r.Writer("logs").Write(data); err != nil {
		t.Fatal(err)
	}
	r.Expect("logs", func(b []byte) bool { return bytes.Contains(b, []byte(caseOrder)) })
	passed := r.Check()
	probe.finish()
	if !exposed {
		if !passed {
			t.Fatal("masked fixture failed its output check", tc.name)
		}
		return caseMasked
	}
	if !passed {
		return "detected"
	}
	return caseMissed
}

func TestAdoptionCases(t *testing.T) {
	t.Parallel()
	var table strings.Builder
	writeComparisonTable(t, &table, "| Application path | masq tags | Manual redact | Key denylist | embargo |\n|---|---|---|---|---|\n")
	for _, tc := range adoptionCases() {
		if adoptionVerdict(t, tc, adoptionOutput(t, tc, "plain")) == caseMasked {
			t.Fatal("fixture did not expose its planted value", tc.name)
		}
		writeComparisonTable(t, &table, "| %s |", tc.name)
		for _, mode := range []string{caseTags, caseManual, caseKeys, comparisonEmbargoName} {
			verdict := adoptionVerdict(t, tc, adoptionOutput(t, tc, mode))
			writeComparisonTable(t, &table, " %s |", verdict)
		}
		writeComparisonTable(t, &table, "\n")
	}
	syncDocTable(t, "../doc/cases.md", "adoption-cases", table.String())
}

func TestAdoptionDeclaredControls(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{caseTags, caseManual, caseKeys, comparisonEmbargoName} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			l := slog.New(adoptionHandler(mode, &out))
			if mode == caseManual {
				l.Info("password=" + caseOpaque)
			} else {
				l.Info("configured", "profile", adoptionProfile{Password: caseOpaque})
			}
			if strings.Contains(out.String(), caseOpaque) || !strings.Contains(out.String(), "[REDACTED]") {
				t.Fatal("declared protection did not run")
			}
		})
	}
}

func TestAdoptionCheckIndependence(t *testing.T) {
	t.Parallel()
	var table strings.Builder
	writeComparisonTable(t, &table, "| Output after embargo masking | Detector only | Whole canary only | Canary with 16-byte fragments |\n|---|---|---|---|\n")
	for _, tc := range adoptionCases() {
		output := adoptionOutput(t, tc, comparisonEmbargoName)
		writeComparisonTable(t, &table, "| %s |", tc.name)
		for mode := range 3 {
			probe := &observationTB{TB: t}
			options := []embargotest.Option{embargotest.WithCanary([]byte(tc.canary))}
			want := tc.name == "unwrapped logger"
			if mode == 0 {
				options = []embargotest.Option{embargotest.WithCanary([]byte("unrelated-fixture-XYZ-987654321"))}
			} else {
				options = append(options, embargotest.WithScanner(embargo.NewScanner(embargo.WithKinds())))
				want = want || tc.name == "hex token"
			}
			if mode == 2 {
				options = append(options, embargotest.WithCanaryFragments(16))
				want = want || tc.name == "split token lines"
			}
			recorder := embargotest.New(probe, options...)
			if _, err := recorder.Writer("logs").Write(output); err != nil {
				t.Fatal(err)
			}
			recorder.Expect("logs", func(b []byte) bool { return bytes.Contains(b, []byte(caseOrder)) })
			detected := !recorder.Check()
			probe.finish()
			if detected != want {
				t.Fatalf("%s mode %d: detected=%t, want %t", tc.name, mode, detected, want)
			}
			result := "clear"
			if detected {
				result = "detected"
			}
			writeComparisonTable(t, &table, " %s |", result)
		}
		writeComparisonTable(t, &table, "\n")
	}
	syncDocTable(t, "../doc/testing-output.md", "check-independence", table.String())
}

func TestAuditDiagnosticRecipe(t *testing.T) {
	t.Parallel()
	const input = `{"order_id":"4111111111111111","request_id":"DEUTDEFF","card":"4242424242424242","authorization":"Bearer pretend-client-value"}`
	const want = `{"order_id":"4111111111111111","request_id":"DEUTDEFF","card":"[REDACTED]","authorization":"[REDACTED]"}`
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN, embargo.KindCredential), embargo.WithMinConfidence(.7))
	output, err := scanner.MaskJSON([]byte(input))
	if err != nil || string(output) != want {
		t.Fatalf("recipe lost diagnostics or retained secrets: %s, %v", output, err)
	}
	// A business label lowers confidence even when its contents really are a card.
	if len(scanner.ScanString("order_id=4111111111111111")) != 0 {
		t.Fatal("documented mislabeled-card tradeoff changed")
	}
	baseline, err := embargo.NewScanner().MaskJSON([]byte(input))
	if err != nil || !strings.Contains(string(baseline), "DEUTDEFF") || strings.Contains(string(baseline), "4111111111111111") {
		t.Fatalf("default ID policy changed: %s", baseline)
	}
}
