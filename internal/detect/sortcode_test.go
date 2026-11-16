package detect

import (
	"fmt"
	"testing"
)

func TestUKSortCodeDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewUKSortCode()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "hyphen separated sort code",
			input:      "sort code: 12-34-56",
			wantLen:    1,
			wantRaw:    sampleSortCode,
			wantMinCon: 0.6,
		},
		{
			name:       "space separated sort code",
			input:      "sort code: 12 34 56",
			wantLen:    1,
			wantRaw:    "12 34 56",
			wantMinCon: 0.6,
		},
		{
			name:       "sort code at start of text",
			input:      "12-34-56 is the sort code",
			wantLen:    1,
			wantRaw:    sampleSortCode,
			wantMinCon: 0.6,
		},
		{
			name:       "sort code at end of text",
			input:      "sort code is 12-34-56",
			wantLen:    1,
			wantRaw:    sampleSortCode,
			wantMinCon: 0.6,
		},
		{
			name:       "mixed separators rejected",
			input:      "code: 12-34 56",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "bare digits without separators",
			input:      "code: 123456",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "preceded by digit is boundary violation",
			input:      "9912-34-56",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "followed by digit is boundary violation",
			input:      "12-34-567",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "part of longer separated sequence",
			input:      "12-34-56-78",
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
			name:       "multiple sort codes",
			input:      "from 12-34-56 to 78-90-12",
			wantLen:    2,
			wantRaw:    "",
			wantMinCon: 0.6,
		},
		{
			name:       "preceded by letter is boundary violation",
			input:      "X12-34-56",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:    "date-like YY-MM-DD pattern rejected (20-12-25)",
			input:   "log: 20-12-25 event",
			wantLen: 0,
		},
		{
			name:    "date-like DD-MM-YY pattern rejected (25-06-15)",
			input:   "log: 25-06-15 event",
			wantLen: 0,
		},
		{
			name:    "date-like with spaces rejected (15 01 23)",
			input:   "log: 15 01 23 event",
			wantLen: 0,
		},
		{
			name:       "non-date sort code with middle > 12 (40-50-60)",
			input:      "sort code: 40-50-60",
			wantLen:    1,
			wantRaw:    "40-50-60",
			wantMinCon: 0.6,
		},
		{
			name:       "non-date sort code with zero outer pairs (00-06-00)",
			input:      "sort code: 00-06-00",
			wantLen:    1,
			wantRaw:    "00-06-00",
			wantMinCon: 0.6,
		},
		{
			name:    "all-zero sort code rejected (00-00-00)",
			input:   "sort code 00-00-00",
			wantLen: 0,
		},
		{
			name:    "all-zero sort code with spaces rejected (00 00 00)",
			input:   "sort code 00 00 00",
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
			if tt.wantRaw != "" && findings[0].RawValue != tt.wantRaw {
				t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
			}
			for _, f := range findings {
				if f.Confidence < tt.wantMinCon {
					t.Errorf("Confidence = %f, want >= %f", f.Confidence, tt.wantMinCon)
				}
			}
		})
	}
}

func TestUKSortCodeDetector_Detail(t *testing.T) {
	t.Parallel()

	d := NewUKSortCode()
	findings := d.Scan([]byte("sort code: 12-34-56"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	detail, ok := findings[0].UKSortCodeDetail()
	if !ok {
		t.Fatal("UKSortCodeDetail() returned false")
	}
	if detail.FormattedValue != sampleSortCode {
		t.Errorf("FormattedValue = %q, want %q", detail.FormattedValue, sampleSortCode)
	}
}

func TestUKSortCodeDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewUKSortCode()
	if d.Name() != NameUKSortCode {
		t.Errorf("Name() = %q, want %q", d.Name(), NameUKSortCode)
	}
}

func TestUKSortCodeDetector_DateLikeWithContext(t *testing.T) {
	t.Parallel()

	d := NewUKSortCode()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantMinCon float64
		wantMaxCon float64
	}{
		{
			name:       "date-like with sort code context accepted at reduced confidence",
			input:      "sort code: 20-12-25",
			wantLen:    1,
			wantMinCon: 0.5,
			wantMaxCon: 0.6,
		},
		{
			name:       "date-like with sortcode context accepted",
			input:      "sortcode 25-06-15",
			wantLen:    1,
			wantMinCon: 0.5,
			wantMaxCon: 0.6,
		},
		{
			name:    "date-like without context still rejected",
			input:   "log: 20-12-25 event",
			wantLen: 0,
		},
		{
			name:       "date-like with bacs context accepted",
			input:      "BACS payment 15-01-23",
			wantLen:    1,
			wantMinCon: 0.5,
			wantMaxCon: 0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d; findings=%+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen > 0 {
				c := findings[0].Confidence
				if c < tt.wantMinCon || c > tt.wantMaxCon {
					t.Errorf("Confidence = %f, want [%f, %f]", c, tt.wantMinCon, tt.wantMaxCon)
				}
			}
		})
	}
}

func TestUKSortCodeDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewUKSortCode()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}

func TestUKSortCodeTrailingSpace(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"01 00 00", "12 34 56"} {
		for _, suffix := range []string{" ", " today", "  "} {
			got := NewUKSortCode().Scan([]byte("sort code: " + raw + suffix))
			if len(got) != 1 || got[0].RawValue != raw {
				t.Errorf("lost %q with suffix %q: %+v", raw, suffix, got)
			}
		}
		if got := NewUKSortCode().Scan([]byte(raw + " 78")); len(got) != 0 {
			t.Errorf("long numeric sequence accepted: %+v", got)
		}
	}
}

func TestSortCodeAdjacentFormats(t *testing.T) {
	t.Parallel()
	input := "sort code: 01 00 00 12-34-56"
	got := NewUKSortCode().Scan([]byte(input))
	if len(got) != 2 || got[0].RawValue != "01 00 00" || got[1].RawValue != sampleSortCode {
		t.Fatalf("adjacent formats: %+v", got)
	}
}

// Enumerate the date-like ambiguity edges independently as decimal examples.
func TestSortCodeDateAmbiguityVectors(t *testing.T) {
	t.Parallel()
	for _, first := range []int{0, 1, 9, 10, 30, 31, 32, 99} {
		for _, month := range []int{0, 1, 9, 10, 12, 13, 99} {
			for _, last := range []int{0, 1, 9, 10, 30, 31, 32, 99} {
				want := month >= 1 && month <= 12 && (first >= 1 && first <= 31 || last >= 1 && last <= 31)
				digits := fmt.Sprintf("%02d%02d%02d", first, month, last)
				got := isSortCodeDateLike(digits[0], digits[1], digits[2], digits[3], digits[4], digits[5])
				if got != want {
					t.Fatalf("date ambiguity %02d-%02d-%02d", first, month, last)
				}
			}
		}
	}
}
