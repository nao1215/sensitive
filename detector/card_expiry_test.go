package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestCardExpiryDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewCardExpiry()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
		wantMinCon float64
	}{
		{
			name:       "exp MM/YY format",
			input:      "exp: 12/25",
			wantLen:    1,
			wantRaw:    "12/25",
			wantMinCon: 0.8,
		},
		{
			name:       "expiry MM/YYYY format",
			input:      "expiry: 01/2030",
			wantLen:    1,
			wantRaw:    "01/2030",
			wantMinCon: 0.8,
		},
		{
			name:       "Expiration with dash separator",
			input:      "Expiration: 06-28",
			wantLen:    1,
			wantRaw:    "06-28",
			wantMinCon: 0.8,
		},
		{
			name:       "valid thru",
			input:      "valid thru 03/27",
			wantLen:    1,
			wantRaw:    "03/27",
			wantMinCon: 0.8,
		},
		{
			name:       "valid through",
			input:      "valid through 11/2026",
			wantLen:    1,
			wantRaw:    "11/2026",
			wantMinCon: 0.8,
		},
		{
			name:       "uppercase EXP",
			input:      "EXP: 09/25",
			wantLen:    1,
			wantRaw:    "09/25",
			wantMinCon: 0.8,
		},
		{
			name: "Japanese keyword",
			// 有効期限: 12/25
			input:      "\xe6\x9c\x89\xe5\x8a\xb9\xe6\x9c\x9f\xe9\x99\x90: 12/25",
			wantLen:    1,
			wantRaw:    "12/25",
			wantMinCon: 0.8,
		},
		{
			name:       "invalid month 00",
			input:      "exp: 00/25",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "invalid month 13",
			input:      "exp: 13/25",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "no keyword no detection",
			input:      "date: 12/25",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "empty input",
			input:      "",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "keyword too far from date",
			input:      "exp: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 12/25",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
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

func TestCardExpiryDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewCardExpiry()
	findings := d.Scan([]byte("exp: 12/25"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	detail, ok := findings[0].CardExpiryDetail()
	if !ok {
		t.Fatal("CardExpiryDetail() returned false")
	}
	if detail.Month != "12" {
		t.Errorf("Month = %q, want %q", detail.Month, "12")
	}
	if detail.Year != "25" {
		t.Errorf("Year = %q, want %q", detail.Year, "25")
	}
}

func TestCardExpiryDetector_Detail_4digitYear(t *testing.T) {
	t.Parallel()

	d := detector.NewCardExpiry()
	findings := d.Scan([]byte("expiry: 01/2030"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	detail, ok := findings[0].CardExpiryDetail()
	if !ok {
		t.Fatal("CardExpiryDetail() returned false")
	}
	if detail.Month != "01" {
		t.Errorf("Month = %q, want %q", detail.Month, "01")
	}
	if detail.Year != "2030" {
		t.Errorf("Year = %q, want %q", detail.Year, "2030")
	}
}

func TestCardExpiryDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewCardExpiry()
	if d.Name() != detector.NameCardExpiry {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameCardExpiry)
	}
}

func TestCardExpiryDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewCardExpiry()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}

func TestCardExpiryDetector_DateBeforeKeyword(t *testing.T) {
	t.Parallel()

	d := detector.NewCardExpiry()
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantRaw string
	}{
		{
			name:    "date before exp keyword",
			input:   "12/29 exp",
			wantLen: 1,
			wantRaw: "12/29",
		},
		{
			name:    "date before expiry keyword",
			input:   "01/2030 expiry",
			wantLen: 1,
			wantRaw: "01/2030",
		},
		{
			name:    "date before Expiration keyword with dash",
			input:   "06-28 Expiration",
			wantLen: 1,
			wantRaw: "06-28",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d; findings=%+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen > 0 && findings[0].RawValue != tt.wantRaw {
				t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
			}
		})
	}
}

func TestCardExpiryDetector_NoFalsePositiveFromExample(t *testing.T) {
	t.Parallel()

	// Regression: "exp" keyword matched inside "example", causing false
	// detection of date patterns near "example". Word boundary checking
	// in findKeywordPositions prevents this.
	d := detector.NewCardExpiry()
	findings := d.Scan([]byte("see example 01/25 for details"))
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0; 'exp' inside 'example' should not trigger detection", len(findings))
	}
}
