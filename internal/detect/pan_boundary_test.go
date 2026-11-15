package detect_test

import (
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

func TestPANRejectsIdentifierFragments(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"d55593266701308e", "a4532015112830366", "4532015112830366f", "_4532015112830366", "4532015112830366_", "a４５３２０１５１１２８３０３６６f"} {
		if got := detect.NewPAN().Scan([]byte(text)); len(got) != 0 {
			t.Errorf("identifier fragment reported as PAN: %q", text)
		}
	}
	for _, text := range []string{"4532015112830366", "card=4532-0151-1283-0366", "v%3D4532015112830366", "カード４５３２０１５１１２８３０３６６"} {
		if got := detect.NewPAN().Scan([]byte(text)); len(got) != 1 {
			t.Errorf("delimited PAN missing: %q", text)
		}
	}
}
