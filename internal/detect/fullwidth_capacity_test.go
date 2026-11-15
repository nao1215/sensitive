package detect

import (
	"math"
	"testing"
)

func TestNormalizationMapSizeRejectsOverflow(t *testing.T) {
	t.Parallel()
	for _, length := range []int{0, 1, 1024} {
		if normalizationMapSize(length) != length+1 {
			t.Fatal("ordinary mapping size changed")
		}
	}
	defer func() {
		if recover() != "embargo: input too large" {
			t.Error("mapping sentinel size overflow was not rejected")
		}
	}()
	normalizationMapSize(math.MaxInt)
}
