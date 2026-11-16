package tests

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

func BenchmarkPublishedScanner(b *testing.B) {
	data, err := os.ReadFile("../testdata/recall.json")
	if err != nil {
		b.Fatal(err)
	}
	var samples []accuracySample
	if err := json.Unmarshal(data, &samples); err != nil {
		b.Fatal(err)
	}
	dirty := map[string]string{}
	for _, sample := range samples {
		if sample.Positive && dirty[sample.Detector] == "" {
			dirty[sample.Detector] = sample.Text + strings.Join(sample.Parts, "")
		}
	}
	names := make([]string, 0, len(dirty)+1)
	for name := range dirty {
		names = append(names, name)
	}
	sort.Strings(names)
	all := make([]string, 0, len(names))
	for _, name := range names {
		all = append(all, dirty[name])
	}
	dirty["all"] = strings.Join(all, "\n")
	names = append(names, "all")
	for _, name := range names {
		scanner := embargo.NewScanner(embargo.WithAll())
		if name != "all" {
			scanner = embargo.NewScanner(embargo.WithKinds(embargo.Kind(name)))
		}
		for _, state := range []string{"clean", "dirty"} {
			text := strings.Repeat("worker completed request reference=example\n", 64)
			if state == "dirty" {
				text = strings.Repeat(dirty[name]+"\n", 64)
			}
			input := []byte(text)
			b.Run(name+"/"+state, func(b *testing.B) {
				b.SetBytes(int64(len(input)))
				b.ReportAllocs()
				for b.Loop() {
					scanner.Scan(input)
				}
			})
		}
	}
}

func BenchmarkPublishedMask(b *testing.B) {
	text := strings.Repeat("email alice@example.com card 4532015112830366\n", 64)
	findings := embargo.NewScanner().ScanString(text)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		embargo.Mask(text, findings)
	}
}

func BenchmarkPublishedRecorder(b *testing.B) {
	data := []byte(strings.Repeat("request accepted\n", 32))
	b.Run("plain", func(b *testing.B) {
		var output bytes.Buffer
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		for b.Loop() {
			output.Reset()
			if _, err := output.Write(data); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("checked", func(b *testing.B) {
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		for b.Loop() {
			recorder := embargotest.New(b)
			if _, err := recorder.Writer("out").Write(data); err != nil {
				b.Fatal(err)
			}
			recorder.Expect("out", func(captured []byte) bool { return bytes.Equal(captured, data) })
			if !recorder.Check() {
				b.Fatal("benchmark output failed")
			}
		}
	})
}

func BenchmarkPublishedSlog(b *testing.B) {
	for _, name := range []string{"plain-clean", "masked-clean", "plain-dirty", "masked-dirty"} {
		b.Run(name, func(b *testing.B) {
			sink := &benchmarkWriter{}
			var handler slog.Handler = slog.NewJSONHandler(sink, nil)
			if strings.HasPrefix(name, "masked") {
				handler = embargo.NewSlogHandler(handler, embargo.NewScanner())
			}
			logger := slog.New(handler)
			value := "public-reference"
			if strings.HasSuffix(name, "dirty") {
				value = "alice@example.com"
			}
			b.ReportAllocs()
			for b.Loop() {
				logger.Info("request accepted", "reference", value)
			}
			if sink.written == 0 {
				b.Fatal("benchmark skipped actual JSON encoding")
			}
		})
	}
}

// benchmarkWriter discards bytes only after the real JSON encoder has run.
type benchmarkWriter struct{ written int }

func (w *benchmarkWriter) Write(data []byte) (int, error) {
	w.written += len(data)
	return len(data), nil
}

func TestBenchmarkEventsMaskTheirSensitiveValues(t *testing.T) {
	t.Parallel()
	for name, attrs := range comparisonEvents() {
		for _, mode := range []string{comparisonMasqName, comparisonEmbargoName} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				checkBenchmarkEvent(t, name, mode, attrs)
			})
		}
	}
}

func checkBenchmarkEvent(t *testing.T, name, mode string, attrs []slog.Attr) {
	t.Helper()
	var out bytes.Buffer
	slog.New(comparisonHandler(mode, &out)).LogAttrs(t.Context(), slog.LevelInfo, "request", attrs...)
	for _, secret := range []string{comparisonEmail, comparisonPassword, comparisonRecovery, "4111111111111111"} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("benchmark configuration leaked its sensitive input")
		}
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if name == comparisonNested || name == comparisonMap {
		field := "user"
		if name == comparisonMap {
			field = "data"
		}
		if raw := record[field]; len(raw) == 0 || raw[0] != '{' {
			t.Fatal("benchmark lost its nested object")
		}
	}
}
