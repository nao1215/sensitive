package benchmarks

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

// BenchmarkCIDefault shares one fixture across both archived revisions in CI.
// Only its package declaration is adapted for the root external test package.
func BenchmarkCIDefault(b *testing.B) {
	scanner := embargo.NewScanner()
	for _, fixture := range []struct {
		name, text string
		dirty      bool
	}{
		{"clean", strings.Repeat("INFO GET /health status=ok duration=2ms\n", 64), false},
		{"dirty", strings.Repeat("email=alice@example.com card=4111111111111111 password=pretend-secret\n", 16), true},
	} {
		input := []byte(fixture.text)
		if (len(scanner.Scan(input)) > 0) != fixture.dirty {
			b.Fatal("benchmark fixture classification changed")
		}
		b.Run(fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				scanner.Scan(input)
			}
		})
	}
	benchmarkStructured(b, scanner)
}

// ciJSON is an adapter event: MaskJSON walks it for zap, zerolog and logrus.
const ciJSON = `{"level":"info","msg":"request accepted","email":"alice@example.com","user_id":42,"path":"/api/v1/orders",` +
	`"env":[{"name":"DB_PASSWORD","value":"pretend"},{"name":"PORT","value":"80"}],"user":{"profile":{"city":"SF"}}}`

// benchmarkStructured covers MaskJSON and the slog handler, the two structured
// paths every sink uses.
func benchmarkStructured(b *testing.B, scanner *embargo.Scanner) {
	b.Helper()
	b.Run("json", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := scanner.MaskJSON([]byte(ciJSON)); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("slog", func(b *testing.B) {
		var probe bytes.Buffer
		slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&probe, nil), scanner)).Info("probe", "email", "alice@example.com")
		if strings.Contains(probe.String(), "alice") {
			b.Fatal("benchmark handler did not mask")
		}
		// DiscardHandler reports every level disabled and would skip the work.
		logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(io.Discard, nil), scanner)) //nolint:sloglint // See above..With("service", "api").WithGroup("request")
		b.ReportAllocs()
		for b.Loop() {
			logger.Info("request accepted", "email", "alice@example.com", "user_id", 42,
				slog.Group("auth", slog.String("name", "token"), slog.String("value", "pretend")), "user", struct{ Name, City string }{"bob", "SF"})
		}
	})
}
