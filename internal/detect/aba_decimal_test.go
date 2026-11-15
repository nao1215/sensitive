package detect_test

import (
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

func TestABADoesNotReadDecimalComponents(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"2026-11-15T00:00:00.021000021+09:00", "2026-11-15T00:00:00.021000021-07:00", "0.021000021", "021000021.0"} {
		if got := detect.NewABARouting().Scan([]byte(text)); len(got) != 0 {
			t.Errorf("decimal component was accepted as a routing number in %q", text)
		}
	}
	if got := detect.NewABARouting().Scan([]byte("routing: .021000021")); len(got) != 1 {
		t.Fatal("punctuation-separated routing number was lost")
	}
}
