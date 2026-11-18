package detect

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// escapedSpace is the percent escape of an ASCII space.
const escapedSpace = "%20"

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

func TestTokenSeparatorsKeepEdgeMarks(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"\u200babc", "abc\u200b", "\u200b"} {
		got, _ := removeTokenSeparators([]byte(input))
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
			got, positions := removeTokenSeparators([]byte(raw))
			if string(got) != sampleAccessKey || len(positions) != len(got)+1 || positions[4] != 4+len(separator) || positions[len(got)] != len(raw) {
				t.Fatalf("separator %U lost token bytes or offsets", r)
			}
			for i, position := range positions[:len(got)] {
				if raw[position] != got[i] || i > 0 && position <= positions[i-1] {
					t.Fatal("normalized bytes do not map to their original positions")
				}
			}
			for _, edge := range []string{separator + "public", "public" + separator} {
				unchanged, mapping := removeTokenSeparators([]byte(edge))
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
	if got := composePositions(nil, parent); !reflect.DeepEqual(got, parent) {
		t.Fatal(got)
	}
	child := []int{0, 1, 2}
	if got := composePositions(child, nil); !reflect.DeepEqual(got, child) {
		t.Fatal(got)
	}
	if composePositions(nil, nil) != nil {
		t.Fatal("identity allocated a map")
	}
}

func TestComposePositionsSentinel(t *testing.T) {
	t.Parallel()
	child := []int{0, 2, 3}
	got := composePositions(child, []int{0, 3, 4, 8})
	if !reflect.DeepEqual(got, []int{0, 4, 8}) || &got[0] != &child[0] {
		t.Fatal(got)
	}
}

func TestComposePositionsLayers(t *testing.T) {
	t.Parallel()
	original := []byte(`password=\x22fixture\x22`)
	first, a := credentialQuotes(original)
	second, b := credentialQuotes(first)
	mapping := composePositions(b, a)
	got := (&Credential{}).Scan(second)
	if len(got) != 1 {
		t.Fatal(got)
	}
	start, end := mapping[got[0].Start], mapping[got[0].End]
	if string(original[start:end]) != "fixture" {
		t.Fatal(start, end)
	}
}

func TestPercentDecodingPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ input, want string }{
		{"a+b", "a+b"}, {"%2520", escapedSpace}, {"%x1%41%", "%x1A%"}, {"%0", "%0"}, {"%41%0", "A%0"}, {"%00%FF", "\x00\xff"},
	} {
		data, positions := decodePercent([]byte(tc.input))
		if string(data) != tc.want {
			t.Fatalf("decode %q: %q", tc.input, data)
		}
		if positions != nil {
			if len(positions) != len(data)+1 {
				t.Fatal("map length")
			}
			if positions[len(data)] != len(tc.input) {
				t.Fatal("sentinel")
			}
		}
	}
	for b := range 256 {
		escaped := fmt.Sprintf("%%%02x", b)
		decoded, positions := decodePercent([]byte(escaped))
		if len(decoded) != 1 || int(decoded[0]) != b || len(positions) != 2 || positions[0] != 0 || positions[1] != 3 {
			t.Fatalf("byte %d", b)
		}
	}
}

func TestPercentPositionMapStaysWithinOriginalSize(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"%41", "prefix%41suffix", "%41%42%43", "prefix%41%0"} {
		decoded, positions := decodePercent([]byte(input))
		// One decoded escape saves two bytes, enough for the end sentinel.
		// Reserving more than the original size is unnecessary and risks overflow.
		if cap(positions) > len(input) || len(positions) != len(decoded)+1 {
			t.Fatalf("position map for %q exceeds its original-size budget", input)
		}
	}
}

func TestFirstNonASCIIFindsEveryPositionAcrossWords(t *testing.T) {
	t.Parallel()
	for length := range 70 {
		ascii := bytes.Repeat([]byte("a"), length)
		if got := firstNonASCII(ascii); got != -1 {
			t.Fatalf("length %d: ASCII input reported %d", length, got)
		}
		for position := range length {
			data := bytes.Clone(ascii)
			data[position] = 0x80
			if position+1 < length {
				data[length-1] = 0xff
			}
			if got := firstNonASCII(data); got != position {
				t.Fatalf("length %d: first non-ASCII at %d, got %d", length, position, got)
			}
		}
	}
}

func TestUnicodeEscapeDecodingPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, want string
	}{
		{"ASCII escape is decoded", `alice\u0040example.com`, emailUserinfoFixture},
		{"hex digits of either case", `a\u002Eb\u002ec`, "a.b.c"},
		{"every character escaped", `\u0061\u0040\u0062`, "a@b"},
		{"non-ASCII escape stays literal", `caf\u00e9`, `caf\u00e9`},
		{"escaped backslash is not an escape", `a\\u0040b`, `a\\u0040b`},
		{"odd backslash run decodes its last escape", `a\\\u0040b`, `a\\@b`},
		{"short or invalid escape stays literal", `\u004 \u00zz \u`, `\u004 \u00zz \u`},
		{"text without escapes is the same slice", "plain", "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			view := NewView([]byte(tt.raw))
			if string(view.Data) != tt.want {
				t.Fatalf("NewView(%q).Data = %q, want %q", tt.raw, view.Data, tt.want)
			}
			if len(view.Positions) > 0 && (len(view.Positions) != len(view.Data)+1 || view.Positions[len(view.Data)] != len(tt.raw)) {
				t.Fatalf("positions %v lack the end sentinel", view.Positions)
			}
		})
	}
}

func TestUnicodeEscapePositionsCoverTheWholeEscape(t *testing.T) {
	t.Parallel()
	raw := `mail alice\u0040example.com end`
	view := NewView([]byte(raw))
	start := bytes.Index(view.Data, []byte("alice"))
	end := start + len("alice@example.com")
	if got := raw[view.Original(start):view.Original(end)]; got != `alice\u0040example.com` {
		t.Fatalf("mapped span %q", got)
	}
}

func TestAppendScanViewMatchesScanView(t *testing.T) {
	t.Parallel()
	prior := Finding{DetectorName: NameEmail, Start: 1, End: 2, Confidence: 1}
	for _, d := range []Detector{NewPAN(), NewEmail(), &Credential{}, NewJPPhone()} {
		for _, raw := range []string{
			"card 4111111111111111 mail bob@example.com",
			"card %34111111111111111 mail bob%40example.com",
			`card 4111111111111111`,
			"card ４１１１１１１１１１１１１１１１ ｂｏｂ＠ｅｘａｍｐｌｅ．ｃｏｍ",
			"password=hunter2 tel 090-1234-5678",
			"nothing here",
		} {
			view := NewView([]byte(raw))
			want := append([]Finding{prior}, ScanView(d, view)...)
			if got := AppendScanView([]Finding{prior}, d, view); !slices.Equal(got, want) {
				t.Errorf("%s on %q: AppendScanView = %v, want %v", d.Name(), raw, got, want)
			}
		}
	}
}

func TestNewViewPlainASCIIIsIdentity(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "plain text 4111", "a\\b", "100%", "café"} {
		view := NewView([]byte(raw))
		plain := plainASCII([]byte(raw))
		if plain && (view.Positions != nil || string(view.Data) != raw) {
			t.Errorf("NewView(%q) changed plain ASCII", raw)
		}
		if plain == (strings.ContainsAny(raw, "\\%") || strings.IndexFunc(raw, func(r rune) bool { return r >= utf8.RuneSelf }) >= 0) {
			t.Errorf("plainASCII(%q) = %v", raw, plain)
		}
	}
}
