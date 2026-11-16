package embargo

import (
	"math/bits"
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

func TestDispatchRetainsMoreThan32Families(t *testing.T) {
	t.Parallel()
	scanner := &Scanner{}
	for range 37 {
		scanner.detectors = append(scanner.detectors, detect.NewMyNumber())
	}
	scanner.hintCache = buildHintCache(scanner.detectors)
	scanner.buildDispatch()
	if got := bits.OnesCount64(scanner.selectDetectors([]byte("123456789012"))); got != 37 {
		t.Fatalf("selected %d families, want 37", got)
	}
}
