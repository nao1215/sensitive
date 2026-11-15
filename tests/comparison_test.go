package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/m-mizutani/masq"

	"github.com/nao1215/embargo"
)

const (
	comparisonPasswordKey    = "password"
	comparisonID             = "u123"
	comparisonOpaque         = "opaque-value"
	comparisonEmailKey       = "email"
	comparisonClean          = "clean"
	comparisonEmail          = "alice@example.com"
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
	return masq.New(masq.WithRegex(regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)), masq.WithRegex(regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)), masq.WithFieldName("Password"), masq.WithFieldName(comparisonPasswordKey), masq.WithFieldName("token"), masq.WithTag("secret"))
}

func comparisonHandler(mode string, out io.Writer) slog.Handler {
	options := &slog.HandlerOptions{}
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
		"flat":          {slog.String(comparisonEmailKey, comparisonEmail), slog.String("card", "4111111111111111")},
		"nested":        {slog.Any("user", comparisonUser{comparisonID, comparisonEmail, comparisonPassword, comparisonRecovery, 17})},
		comparisonMap:   {slog.Any("data", map[string]any{comparisonEmailKey: comparisonEmail, "card": "4111111111111111", comparisonPasswordKey: comparisonPassword, "count": 17})},
		comparisonClean: {slog.String("status", "accepted"), slog.Int("count", 17), slog.Bool("ok", true)},
	}
	large := make([]slog.Attr, 0, 50)
	for i := range 48 {
		large = append(large, slog.String(fmt.Sprintf("field%d", i), "clean application value"))
	}
	events["large50"] = append(large, events["flat"]...)
	return events
}

func BenchmarkComparison(b *testing.B) {
	for name, attrs := range comparisonEvents() {
		b.Run(name, func(b *testing.B) {
			for _, mode := range []string{comparisonMasqName, comparisonEmbargoName} {
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
