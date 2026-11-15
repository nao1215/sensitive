package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	dlp "github.com/bytedance/godlp"
	"github.com/bytedance/godlp/dlpheader"
	slogformatter "github.com/samber/slog-formatter"
	mask "github.com/showa-93/go-mask"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

func formatterHandler(out io.Writer) slog.Handler {
	return slogformatter.NewFormatterHandler(slogformatter.PIIFormatter(comparisonEmailKey), slogformatter.PIIFormatter("card"), slogformatter.PIIFormatter("user"), slogformatter.PIIFormatter("data"))(slog.NewJSONHandler(out, nil))
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
	b.Run("godlp", func(b *testing.B) {
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
	masker := comparisonMasker()
	scanner := comparisonScanner()
	b.Run("go_mask", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			safe, err := masker.Mask(value)
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
