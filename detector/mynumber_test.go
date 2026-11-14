package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestMyNumberDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
		wantMinCon float64
	}{
		{
			name:       "valid My Number (check digit 0)",
			input:      "mynumber: 123456789018",
			wantLen:    1,
			wantRaw:    "123456789018",
			wantMinCon: 0.9,
		},

		{
			name:       "hyphen-separated My Number",
			input:      "1234-5678-9018",
			wantLen:    1,
			wantRaw:    "1234-5678-9018",
			wantMinCon: 0.9,
		},
		{
			name:       "space-separated My Number",
			input:      "1234 5678 9018",
			wantLen:    1,
			wantRaw:    "1234 5678 9018",
			wantMinCon: 0.9,
		},

		// False positives
		{
			name:    "12 digits with invalid check digit",
			input:   "123456789012",
			wantLen: 0,
		},
		{
			name:    "11 digits",
			input:   "12345678901",
			wantLen: 0,
		},
		{
			name:    "13 digits",
			input:   "1234567890123",
			wantLen: 0,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen > 0 && tt.wantRaw != "" {
				if findings[0].RawValue != tt.wantRaw {
					t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
				}
			}
			if tt.wantLen > 0 && tt.wantMinCon > 0 {
				if findings[0].Confidence < tt.wantMinCon {
					t.Errorf("Confidence = %f, want >= %f", findings[0].Confidence, tt.wantMinCon)
				}
			}
		})
	}
}

func TestMyNumberDetector_FullWidthRawValue(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	// 123456789018 in full-width digits.
	input := "１２３４５６７８９０１８"
	findings := d.Scan([]byte(input))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.RawValue != input {
		t.Errorf("RawValue = %q, want %q", f.RawValue, input)
	}
	if input[f.Start:f.End] != f.RawValue {
		t.Errorf("input[Start:End] = %q, RawValue = %q", input[f.Start:f.End], f.RawValue)
	}
}

func TestMyNumberDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	findings := d.Scan([]byte("123456789018"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].MyNumberDetail()
	if !ok {
		t.Fatal("MyNumberDetail() returned false")
	}
	if !detail.CheckDigitValid {
		t.Error("CheckDigitValid = false, want true")
	}
}

func TestMyNumberDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	if d.Name() != detector.NameMyNumber {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameMyNumber)
	}
}

func TestMyNumberDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	hints := d.Hints()
	// Hints returns nil so the Scanner always runs My Number detection.
	// My Number can start with any digit 0-9, so single-digit hints would
	// match virtually every input and provide no filtering benefit.
	if hints != nil {
		t.Errorf("Hints() = %v, want nil", hints)
	}
}

func TestMyNumberDetector_PrecededByAlpha(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	// Digits preceded by alpha should not match.
	findings := d.Scan([]byte("x123456789018"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for alpha-preceded mynumber, want 0", len(findings))
	}
}

func TestMyNumberDetector_FollowedByDigit(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	// 13 digits: the 12-digit candidate is followed by another digit.
	findings := d.Scan([]byte("1234567890189"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for 13 digits, want 0", len(findings))
	}
}

func TestMyNumberDetector_RemainderZero(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	// All zeros: sum=0, remainder=0%11=0 (<=1), expected check digit=0.
	// This exercises the "remainder <= 1" branch in isValidMyNumber.
	findings := d.Scan([]byte("000000000000"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Confidence < 0.9 {
		t.Errorf("Confidence = %f, want >= 0.9", findings[0].Confidence)
	}
}

func TestMyNumberDetector_RemainderOne(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	// "100000010000": sum=11, remainder=11%11=0, expected=0, check=0.
	// Another case exercising remainder <= 1.
	findings := d.Scan([]byte("100000010000"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestMyNumberDetector_TrailingHyphen(t *testing.T) {
	t.Parallel()

	d := detector.NewMyNumber()
	// Trailing hyphen should be trimmed.
	findings := d.Scan([]byte("1234-5678-9018-"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RawValue != "1234-5678-9018" {
		t.Errorf("RawValue = %q, want %q", findings[0].RawValue, "1234-5678-9018")
	}
}
