package detect

import (
	"fmt"
	"strings"
	"testing"
)

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
		{"phone parentheses", "(03)1234-5679)", phoneSeparator, "0312345679", 13},
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

func TestNumericHasCandidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d   Detector
		min int
	}{{NewPAN(), panMinDigits}, {NewMyNumber(), myNumberDigits}, {NewJPPhone(), jpPhoneMinDigits}, {NewUSPhone(), usPhoneDigits}, {NewABARouting(), abaDigits}, {NewUKSortCode(), sortCodeDigits}} {
		short := strings.Repeat("1-", tc.min-1)
		if HasCandidate(tc.d, []byte(short)) || !HasCandidate(tc.d, []byte(short+"1")) {
			t.Errorf("%s: want a candidate from exactly %d digits", tc.d.Name(), tc.min)
		}
		if !HasCandidate(tc.d, []byte(short+"１")) {
			t.Errorf("%s: a full-width digit must count", tc.d.Name())
		}
	}
	if hasWideDigits([]byte("\xef\xbc"), 1) || hasWideDigits([]byte("\xef\xbc\x9a"), 1) || hasWideDigits([]byte("\xef\xbd\x90"), 1) || hasWideDigits([]byte("\xef\xbc\x8f"), 1) {
		t.Error("only U+FF10 to U+FF19 are full-width digits")
	}
}

func TestSplitsRunOnlyShortMultiGroupRuns(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		group, digits int
		want          bool
	}{
		{group: 1, digits: 17, want: true},
		{group: 16, digits: 32, want: true},
		{group: 4, digits: 33, want: false},
		{group: 16, digits: 16, want: false},
	} {
		if got := splitsRun(tc.group, tc.digits, 13, 19); got != tc.want {
			t.Errorf("splitsRun(%d, %d) = %v", tc.group, tc.digits, got)
		}
	}
	if digitRun([]byte("12a3"), 0) != 2 || digitRun([]byte("12"), 2) != 0 {
		t.Error("digitRun miscounts")
	}
}

func TestLeadingGroupsLongestFirst(t *testing.T) {
	t.Parallel()
	data := []byte("12 345  6789-0")
	var parts []string
	leadingGroups(data, 0, len(data), 10, 2, func(end, count int) bool {
		parts = append(parts, fmt.Sprintf("%s/%d", data[:end], count))
		return false
	})
	if got := strings.Join(parts, ","); got != "12 345  6789/9,12 345/5,12/2" {
		t.Fatalf("parts = %s", got)
	}
	var stopped []int
	if !leadingGroups(data, 0, len(data), 10, 2, func(end, _ int) bool { stopped = append(stopped, end); return true }) || len(stopped) != 1 {
		t.Fatal("leadingGroups did not stop at the accepted part")
	}
	if leadingGroups(data, 0, len(data), 10, 6, func(int, int) bool { return true }) == false {
		t.Fatal("a part of 9 digits is at least 6")
	}
	calls := 0
	leadingGroups(data, 0, len(data), 10, 10, func(int, int) bool { calls++; return false })
	if calls != 0 {
		t.Fatal("parts shorter than minDigits were tried")
	}
}
