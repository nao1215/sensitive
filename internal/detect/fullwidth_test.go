package detect

import (
	"bytes"
	"math"
	"testing"
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
			wantNormalized: sampleMobile,
		},
		{
			name:           emptyInputCase,
			input:          "",
			wantNormalized: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			normalized, posMap := NormalizeFullWidthDigits([]byte(tt.input))
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

func TestNormalizationIdentityDifferential(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		input := append([]byte("４２４２ "), byte(n))
		for _, data := range [][]byte{input, {byte(n)}, []byte(samplePAN), nil} {
			want, indices := NormalizeFullWidthDigits(data)
			got, positions := normalizeDigits(data)
			if !bytes.Equal(got, want) {
				t.Fatal("normalization differs")
			}
			for i := 0; i <= len(got); i++ {
				if originalPosition(positions, i) != indices[i] {
					t.Fatal("position differs")
				}
			}
		}
	}
}
