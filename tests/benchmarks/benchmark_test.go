package benchmarks

import (
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
}
