package detect

import (
	"bytes"
	"math"
	"reflect"
	"strings"
	"testing"
	"unicode"
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

func TestUnicodeNormalizationOffsets(t *testing.T) {
	t.Parallel()
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !unicode.Is(unicode.Pd, r) && !unicode.Is(unicode.Zs, r) && !unicode.Is(unicode.Cf, r) && (!unicode.Is(unicode.Sm, r) || !unicode.Is(unicode.Dash, r)) {
			continue
		}
		separator := string(r)
		raw := "４１１１" + separator + "１１１１" + separator + "１１１１" + separator + "１１１１"
		input := "日本語: " + raw + "!"
		findings := NewPAN().Scan([]byte(input))
		if len(findings) != 1 || findings[0].Start != len("日本語: ") || findings[0].End != len(input)-1 || input[findings[0].Start:findings[0].End] != raw {
			t.Fatalf("bad original offsets: %q %v", input, findings)
		}
		normalized, positions := NormalizeFullWidthDigits([]byte(input))
		if len(positions) != len(normalized)+1 || positions[len(normalized)] != len(input) {
			t.Fatal("invalid sentinel")
		}
		for i := 1; i < len(positions); i++ {
			if positions[i] <= positions[i-1] {
				t.Fatal("nonmonotone byte mapping")
			}
		}
		if r > unicode.MaxASCII && strings.Contains(string(normalized), separator) {
			t.Fatal("separator not normalized")
		}
	}
}

func TestFullwidthRejectedBoundaries(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"\u200babc", "abc\u200b", "\u200b"} {
		got, _ := RemoveTokenSeparators([]byte(input))
		if string(got) != input {
			t.Fatal("non-interior mark removed")
		}
	}
}

func TestTokenSeparatorCategoryProperty(t *testing.T) {
	t.Parallel()
	for r := rune(unicode.MaxASCII + 1); r <= unicode.MaxRune; r++ {
		if !unicode.Is(unicode.Pd, r) && !unicode.Is(unicode.Zs, r) && !unicode.Is(unicode.Cf, r) && (!unicode.Is(unicode.Sm, r) || !unicode.Is(unicode.Dash, r)) {
			continue
		}
		for _, repetitions := range []int{1, 3} {
			separator := strings.Repeat(string(r), repetitions)
			raw := "AKIA" + separator + "IOSFODNN7EXAMPLE"
			got, positions := RemoveTokenSeparators([]byte(raw))
			if string(got) != sampleAccessKey || len(positions) != len(got)+1 || positions[4] != 4+len(separator) || positions[len(got)] != len(raw) {
				t.Fatalf("separator %U lost token bytes or offsets", r)
			}
			for i, position := range positions[:len(got)] {
				if raw[position] != got[i] || i > 0 && position <= positions[i-1] {
					t.Fatal("normalized bytes do not map to their original positions")
				}
			}
			for _, edge := range []string{separator + "public", "public" + separator} {
				unchanged, mapping := RemoveTokenSeparators([]byte(edge))
				if string(unchanged) != edge || mapping != nil {
					t.Fatal("non-interior separator changed")
				}
			}
		}
	}
}

func TestComposePositionsIdentity(t *testing.T) {
	t.Parallel()
	parent := []int{0, 3, 4}
	if got := ComposePositions(nil, parent); !reflect.DeepEqual(got, parent) {
		t.Fatal(got)
	}
	child := []int{0, 1, 2}
	if got := ComposePositions(child, nil); !reflect.DeepEqual(got, child) {
		t.Fatal(got)
	}
	if ComposePositions(nil, nil) != nil {
		t.Fatal("identity allocated a map")
	}
}

func TestComposePositionsSentinel(t *testing.T) {
	t.Parallel()
	child := []int{0, 2, 3}
	got := ComposePositions(child, []int{0, 3, 4, 8})
	if !reflect.DeepEqual(got, []int{0, 4, 8}) || &got[0] != &child[0] {
		t.Fatal(got)
	}
}

func TestComposePositionsLayers(t *testing.T) {
	t.Parallel()
	original := []byte(`password=\x22fixture\x22`)
	first, a := credentialQuotes(original)
	second, b := credentialQuotes(first)
	mapping := ComposePositions(b, a)
	got := (&Credential{}).Scan(second)
	if len(got) != 1 {
		t.Fatal(got)
	}
	start, end := mapping[got[0].Start], mapping[got[0].End]
	if string(original[start:end]) != "fixture" {
		t.Fatal(start, end)
	}
}
