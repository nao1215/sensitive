package detect

import (
	"testing"

	"github.com/nao1215/embargo/internal/ascii"
)

func TestOverlapsFindingTreatsTouchingSpansAsSeparate(t *testing.T) {
	t.Parallel()

	reported := []Finding{{Start: 10, End: 20}}
	for _, tc := range []struct {
		start, end int
		want       bool
	}{
		{0, 10, false},  // ends where the finding starts
		{20, 30, false}, // starts where the finding ends
		{0, 11, true},
		{19, 30, true},
		{12, 15, true},
	} {
		if got := overlapsFinding(reported, tc.start, tc.end); got != tc.want {
			t.Errorf("overlapsFinding([%d,%d)) = %v, want %v", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestNearRuleDeduplicationModes(t *testing.T) {
	t.Parallel()

	// Two keywords share one digit run: start mode reports it once, and a
	// rejected candidate is not remembered, so a later accept can still report it.
	keywords := newKeywordSet([][]byte{[]byte("id"), []byte("no")})
	data := []byte("id no 12345678")
	calls := 0
	rule := nearRule{keywords: keywords, class: ascii.IsDigit, radius: 30, minLen: 8, maxLen: 8,
		accept: func([]byte, digitSequence) (float64, bool) { calls++; return 0.5, calls > 1 }}
	got := rule.scan(nil, NameCVV, data, nil)
	if len(got) != 1 || got[0].Start != 6 || got[0].End != 14 || calls != 2 {
		t.Fatalf("start mode: %+v after %d accept calls", got, calls)
	}
	rule.overlap = true
	calls = 1
	if got := rule.scan([]Finding{{Start: 7, End: 8}}, NameCVV, data, nil); len(got) != 1 || calls != 1 {
		t.Fatalf("overlap mode must skip a run overlapping dst: %+v", got)
	}
}
