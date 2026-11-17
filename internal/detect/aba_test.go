package detect

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestABARoutingDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewABARouting()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "JPMorgan Chase routing number",
			input:      "routing: 021000021",
			wantLen:    1,
			wantRaw:    "021000021",
			wantMinCon: 0.8,
		},
		{
			name:       "Bank of America routing number",
			input:      "ABA 026009593",
			wantLen:    1,
			wantRaw:    "026009593",
			wantMinCon: 0.8,
		},
		{
			name:       "Wells Fargo routing number",
			input:      "RTN 121000248",
			wantLen:    1,
			wantRaw:    "121000248",
			wantMinCon: 0.8,
		},
		{
			name:       "routing number at start of text",
			input:      "021000021 is the routing number",
			wantLen:    1,
			wantRaw:    "021000021",
			wantMinCon: 0.8,
		},
		{
			name:       "routing number at end of text",
			input:      "the routing number is 021000021",
			wantLen:    1,
			wantRaw:    "021000021",
			wantMinCon: 0.8,
		},
		{
			name:       "invalid checksum",
			input:      "routing: 021000022",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "invalid prefix 00",
			input:      "number: 001000021",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "invalid prefix 13",
			input:      "number: 131000021",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "too few digits 8",
			input:      "number: 02100002",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "too many digits 10",
			input:      "number: 0210000210",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "preceded by letter is boundary violation",
			input:      "X021000021",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       emptyInputCase,
			input:      "",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "thrift range prefix 21",
			input:      "routing: 211370545",
			wantLen:    1,
			wantRaw:    "211370545",
			wantMinCon: 0.8,
		},
		{
			name:       "electronic range prefix 61 with valid checksum",
			input:      "routing: 610000005",
			wantLen:    1,
			wantRaw:    "610000005",
			wantMinCon: 0.8,
		},
		{
			name:       "multiple routing numbers in one line",
			input:      "from 021000021 to 026009593",
			wantLen:    2,
			wantRaw:    "",
			wantMinCon: 0.8,
		},
		{
			name:    "electronic prefix with failed checksum and context is now rejected",
			input:   "routing: 611070545",
			wantLen: 0,
		},
		{
			name:    "electronic prefix with failed checksum and no context is rejected",
			input:   "number: 611070545",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d; findings=%+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen == 0 {
				return
			}
			if tt.wantRaw != "" && tt.input[findings[0].Start:findings[0].End] != tt.wantRaw {
				t.Errorf("matched text = %q, want %q", tt.input[findings[0].Start:findings[0].End], tt.wantRaw)
			}
			for _, f := range findings {
				if f.Confidence < tt.wantMinCon {
					t.Errorf("Confidence = %f, want >= %f", f.Confidence, tt.wantMinCon)
				}
			}
		})
	}
}

func TestABARoutingDetector_ChecksumFailedAlwaysRejected(t *testing.T) {
	t.Parallel()

	d := NewABARouting()
	// Even with routing context keyword, checksum failure must be rejected.
	findings := d.Scan([]byte("routing: 611070545"))
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (checksum failure must always be rejected)", len(findings))
	}
}

func TestABARoutingDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewABARouting()
	findings := d.Scan([]byte("routing: 021000021"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	matched := "routing: 021000021"[findings[0].Start:findings[0].End]
	if !validABAPrefix([]byte(matched)) {
		t.Fatal("valid Federal Reserve routing symbol rejected")
	}
}

func TestABARoutingDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewABARouting()
	if d.Name() != NameABARouting {
		t.Errorf("Name() = %q, want %q", d.Name(), NameABARouting)
	}
}

func TestABARoutingDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewABARouting()
	if d.Hints() != nil {
		t.Errorf("Hints() = %v, want nil", d.Hints())
	}
}

func TestABADoesNotReadDecimalComponents(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"2026-11-15T00:00:00.021000021+09:00", "2026-11-15T00:00:00.021000021-07:00", "0.021000021", "021000021.0"} {
		if got := NewABARouting().Scan([]byte(text)); len(got) != 0 {
			t.Errorf("decimal component was accepted as a routing number in %q", text)
		}
	}
	if got := NewABARouting().Scan([]byte("routing: .021000021")); len(got) != 1 {
		t.Fatal("punctuation-separated routing number was lost")
	}
}

func TestABAChecksumAndDistrictContract(t *testing.T) {
	t.Parallel()
	for prefix := range 100 {
		raw := []byte{byte('0' + prefix/10), byte('0' + prefix%10), '1', '2', '3', '4', '5', '6', '0'}
		sum := 0
		for i, b := range raw[:8] {
			sum += int(b-'0') * []int{3, 7, 1}[i%3]
		}
		raw[8] = byte('0' + (10-sum%10)%10)
		valid := prefix >= 1 && prefix <= 12 || prefix >= 21 && prefix <= 32 || prefix >= 61 && prefix <= 72 || prefix == 80
		if (len(NewABARouting().Scan(raw)) == 1) != valid {
			t.Fatalf("district %s", raw)
		}
		if !valid {
			continue
		}
		for i := range raw {
			bad := bytes.Clone(raw)
			bad[i] = '0' + (bad[i]-'0'+1)%10
			if validateABAChecksum(bad) {
				t.Fatalf("checksum position %d", i)
			}
		}
	}
}

func BenchmarkABALeadingWhitespace(b *testing.B) {
	input := []byte(strings.Repeat(" ", 1<<20) + strings.Repeat("021000021 ", 10000))
	detector := NewABARouting()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		if len(detector.Scan(input)) != 10000 {
			b.Fatal("standalone ABA values were lost after leading whitespace")
		}
	}
}

func TestAbaRejectedBoundaries(t *testing.T) {
	t.Parallel()
	if validateABAChecksum(nil) || validABAPrefix(nil) {
		t.Fatal("invalid routing metadata accepted")
	}
	if got := NewABARouting().Scan([]byte("021000021x")); len(got) != 0 {
		t.Fatal("routing suffix accepted")
	}
}

func TestABAExceptionCounterProperty(t *testing.T) {
	t.Parallel()
	d := NewABARouting()
	for n := range 100 {
		code := fmt.Sprintf("02%06d", n)
		sum := 0
		for i, b := range []byte(code) {
			sum += int(b-'0') * []int{3, 7, 1}[i%3]
		}
		code += strconv.Itoa((10 - sum%10) % 10)
		if got := d.Scan([]byte(code + " double-hummer alignment exceptions")); len(got) != 0 {
			t.Errorf("context accepted: %s: %+v", code, got)
		}
		for _, positive := range []string{code, "ABA: " + code} {
			if got := d.Scan([]byte(positive)); len(got) != 1 {
				t.Errorf("positive lost: %s: %+v", positive, got)
			}
		}
	}
}

func TestABALogSequenceProperty(t *testing.T) {
	t.Parallel()
	d := NewABARouting()
	for n := range 100 {
		code := fmt.Sprintf("02%06d", n)
		sum := 0
		for i, b := range []byte(code) {
			sum += int(b-'0') * []int{3, 7, 1}[i%3]
		}
		code += strconv.Itoa((10 - sum%10) % 10)
		if got := d.Scan([]byte("Creating new log file: log." + code)); len(got) != 0 {
			t.Errorf("context accepted: %s: %+v", code, got)
		}
		for _, positive := range []string{code, "ABA: " + code} {
			if got := d.Scan([]byte(positive)); len(got) != 1 {
				t.Errorf("positive lost: %s: %+v", positive, got)
			}
		}
	}
}

func TestABAChecksumSingleDigitChanges(t *testing.T) {
	t.Parallel()
	digits := []byte("021000021")
	for i, original := range digits {
		for replacement := byte('0'); replacement <= '9'; replacement++ {
			digits[i] = replacement
			if validateABAChecksum(digits) != (replacement == original) {
				t.Fatal(i, replacement)
			}
		}
		digits[i] = original
	}
}

func TestABARoutingSymbolRanges(t *testing.T) {
	t.Parallel()
	for value := range 100 {
		input := []byte{byte('0' + value/10), byte('0' + value%10)}
		want := value >= 1 && value <= 12 || value >= 21 && value <= 32 || value >= 61 && value <= 72 || value == 80
		if validABAPrefix(input) != want {
			t.Fatalf("routing symbol %q: want %v", input, want)
		}
	}
}
