package ascii_test

import (
	"testing"

	"github.com/nao1215/sensitive/internal/ascii"
)

func TestHasLetter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"lowercase letter", []byte("abc"), true},
		{"uppercase letter", []byte("ABC"), true},
		{"mixed", []byte("123a456"), true},
		{"digits only", []byte("123456"), false},
		{"empty", []byte{}, false},
		{"symbols only", []byte("!@#$%"), false},
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
		input []byte
		want  string
	}{
		{"all uppercase", []byte("ABC"), "abc"},
		{"mixed case", []byte("AbC"), "abc"},
		{"already lowercase", []byte("abc"), "abc"},
		{"digits unchanged", []byte("123"), "123"},
		{"empty", []byte{}, ""},
		{"non-ASCII unchanged", []byte{0x80, 'A', 0xFF}, string([]byte{0x80, 'a', 0xFF})},
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
		{"uppercase A", 'A', 'a'},
		{"uppercase Z", 'Z', 'z'},
		{"already lowercase", 'a', 'a'},
		{"digit unchanged", '0', '0'},
		{"symbol unchanged", '@', '@'},
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
