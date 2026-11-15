package ascii_test

import (
	"testing"

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
