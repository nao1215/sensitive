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
			var handler slog.Handler = slog.NewJSONHandler(&benchmarkWriter{}, nil)
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
		})
	}
}

// benchmarkWriter discards bytes only after the real JSON encoder has run.
type benchmarkWriter struct{ written int }

func (w *benchmarkWriter) Write(data []byte) (int, error) {
	w.written += len(data)
	return len(data), nil
}
