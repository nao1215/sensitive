package ascii_test

import (
	"encoding/hex"
	"strings"
	"testing"
	"unicode"

	"github.com/nao1215/embargo/internal/ascii"
)

func TestHasLetter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{name: "lowercase letter", input: []byte("abc"), want: true},
		{name: "uppercase letter", input: []byte("ABC"), want: true},
		{name: "mixed", input: []byte("123a456"), want: true},
		{name: "digits only", input: []byte("123456"), want: false},
		{name: "empty", input: []byte{}, want: false},
		{name: "symbols only", input: []byte("!@#$%"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ascii.HasLetter(tt.input)
			if got != tt.want {
				t.Errorf("HasLetter(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLowerCopy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		want  string
		input []byte
	}{
		//nolint:goconst // Each test states its fixture and expected result independently.
		{name: "all uppercase", input: []byte("ABC"), want: "abc"},
		{name: "mixed case", input: []byte("AbC"), want: "abc"},
		{name: "already lowercase", input: []byte("abc"), want: "abc"},
		{name: "digits unchanged", input: []byte("123"), want: "123"},
		{name: "empty", input: []byte{}, want: ""},
		{name: "non-ASCII unchanged", input: []byte{0x80, 'A', 0xFF}, want: string([]byte{0x80, 'a', 0xFF})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ascii.LowerCopy(tt.input)
			if string(got) != tt.want {
				t.Errorf("LowerCopy(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input byte
		want  byte
	}{
		{name: "uppercase A", input: 'A', want: 'a'},
		{name: "uppercase Z", input: 'Z', want: 'z'},
		{name: "already lowercase", input: 'a', want: 'a'},
		{name: "digit unchanged", input: '0', want: '0'},
		{name: "symbol unchanged", input: '@', want: '@'},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ascii.ToLower(tt.input)
			if got != tt.want {
				t.Errorf("ToLower(%c) = %c, want %c", tt.input, got, tt.want)
			}
		})
	}
}

func TestEveryByteAgainstUnicodeASCIIOracle(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		// #nosec G115 -- Exhaust the exact byte domain.
		b := byte(n)
		wantLetter := n < 128 && unicode.IsLetter(rune(n))
		if ascii.HasLetter([]byte{b}) != wantLetter {
			t.Fatalf("letter boundary at byte %d", n)
		}
		want := b
		if n < 128 {
			want = byte(unicode.ToLower(rune(n)))
		} // #nosec G115 -- ASCII case conversion stays in the byte domain.
		if ascii.ToLower(b) != want || ascii.LowerCopy([]byte{b})[0] != want {
			t.Fatalf("lowercase boundary at byte %d", n)
		}
	}
}

func TestDecodeHexAlphabet(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		decoded, err := hex.DecodeString("0" + string(rune(n)))
		value, ok := ascii.DecodeHex(byte(n))
		if ok != (err == nil) || ok && value != decoded[0] {
			t.Fatal(n, value, ok)
		}
	}
}

// Every byte class agrees with the standard library on all 256 bytes, so detectors share one alphabet.
func TestByteClasses(t *testing.T) {
	t.Parallel()
	const (
		digits = "0123456789"
		upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower  = "abcdefghijklmnopqrstuvwxyz"
	)
	for n := range 256 {
		b := byte(n)
		isDigit := strings.IndexByte(digits, b) >= 0
		isUpper := strings.IndexByte(upper, b) >= 0
		isLower := strings.IndexByte(lower, b) >= 0
		_, hexErr := hex.DecodeString("0" + string(b))
		checks := []struct {
			name      string
			got, want bool
		}{
			{"IsDigit", ascii.IsDigit(b), isDigit},
			{"IsUpper", ascii.IsUpper(b), isUpper},
			{"IsLower", ascii.IsLower(b), isLower},
			{"IsAlpha", ascii.IsAlpha(b), isUpper || isLower},
			{"IsAlphaNum", ascii.IsAlphaNum(b), isUpper || isLower || isDigit},
			{"IsHexDigit", ascii.IsHexDigit(b), hexErr == nil},
		}
		for _, c := range checks {
			if c.got != c.want {
				t.Fatalf("%s(%#x) = %v, want %v", c.name, b, c.got, c.want)
			}
		}
		wantUpper, wantLower := b, b
		if isLower {
			wantUpper = b - 'a' + 'A'
		}
		if isUpper {
			wantLower = b - 'A' + 'a'
		}
		if got := ascii.ToUpper(b); got != wantUpper {
			t.Fatalf("ToUpper(%#x) = %#x, want %#x", b, got, wantUpper)
		}
		if got := ascii.IsAlphaNumRune(rune(b)); got != (isUpper || isLower || isDigit) {
			t.Fatalf("IsAlphaNumRune(%#x) = %v", b, got)
		}
		if got := ascii.ToLowerRune(rune(b)); got != rune(wantLower) {
			t.Fatalf("ToLowerRune(%#x) = %#x", b, got)
		}
		if got := ascii.LowerString(string([]byte{'X', b})); got != string([]byte{'x', wantLower}) {
			t.Fatalf("LowerString(%#x) = %q", b, got)
		}
	}
}

func TestRuneClassesIgnoreNonASCII(t *testing.T) {
	t.Parallel()
	for _, r := range []rune{'０', 'Ａ', 'ａ', 'İ', 0x10FFFF, -1} {
		if ascii.IsAlphaNumRune(r) || ascii.ToLowerRune(r) != r {
			t.Fatalf("non-ASCII rune %U treated as ASCII", r)
		}
	}
}
