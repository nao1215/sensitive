package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestNormalizeFullWidthDigits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          string
		wantNormalized string
	}{
		{
			name:           "ASCII only (no change)",
			input:          "hello 1234",
			wantNormalized: "hello 1234",
		},
		{
			name:           "full-width digits",
			input:          "０１２３４５６７８９",
			wantNormalized: "0123456789",
		},
		{
			name:           "mixed ASCII and full-width",
			input:          "card ４５３２0151",
			wantNormalized: "card 45320151",
		},
		{
			name:           "full-width hyphen U+FF0D",
			input:          "０９０－１２３４－５６７８",
			wantNormalized: "090-1234-5678",
		},
		{
			name:           "empty input",
			input:          "",
			wantNormalized: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			normalized, posMap := detector.NormalizeFullWidthDigits([]byte(tt.input))
			if string(normalized) != tt.wantNormalized {
				t.Errorf("normalized = %q, want %q", string(normalized), tt.wantNormalized)
			}
			// posMap should have len(normalized)+1 entries (including sentinel).
			if len(posMap) != len(normalized)+1 {
				t.Errorf("posMap length = %d, want %d", len(posMap), len(normalized)+1)
			}
		})
	}
}
