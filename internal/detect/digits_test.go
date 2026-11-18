package detect

import "testing"

func TestHasDigitsCountsOnlyASCIIDigits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		n     int
		want  bool
	}{
		{"twelve digits are fewer than a card", "field 1234-5678-9012", panMinDigits, false},
		{"thirteen digits reach a card", "4222222222222", panMinDigits, true},
		{"digits are counted across separators", "a1b2c3", 3, true},
		{"full-width digits are not ASCII", "４１１１", 1, false},
		{"empty input has no digits", "", 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasDigits([]byte(tt.input), tt.n); got != tt.want {
				t.Errorf("hasDigits(%q, %d) = %v, want %v", tt.input, tt.n, got, tt.want)
			}
		})
	}
}

func TestHasDigitRunNeedsConsecutiveDigits(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]bool{"1234": true, "a12b34": false, "12 3456": true, "123": false} {
		if got := hasDigitRun([]byte(input), 4); got != want {
			t.Errorf("hasDigitRun(%q, 4) = %v, want %v", input, got, want)
		}
	}
}

func TestAppendSeparatedDigits(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		data      string
		separator func(byte) bool
		digits    string
		end       int
	}{
		{"card groups", "4111 1111-1111 1111 x", cardSeparator, "4111111111111111", 19},
		{"trailing separators stay outside", "0312 ", cardSeparator, "0312", 4},
		{"card rejects parentheses", "(03)1234", cardSeparator, "", 0},
		{"phone parentheses", "(03)1234-5678)", phoneSeparator, "0312345678", 13},
		{"letters end the run", "12ab34", phoneSeparator, "12", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			digits, end := appendSeparatedDigits([]byte(tc.data), 0, nil, tc.separator)
			if string(digits) != tc.digits || end != tc.end {
				t.Fatalf("got %q end %d, want %q end %d", digits, end, tc.digits, tc.end)
			}
		})
	}
}

func TestAllDigits(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]bool{"": true, "0123456789": true, "12a": false, "\xef\xbc\x91": false} {
		if got := allDigits([]byte(input)); got != want {
			t.Errorf("allDigits(%q) = %v, want %v", input, got, want)
		}
	}
}
