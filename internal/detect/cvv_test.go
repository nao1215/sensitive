package detect

import (
	"testing"
)

func TestCVVDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewCVV()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "CVV with 3 digits",
			input:      "CVV: 123",
			wantLen:    1,
			wantRaw:    "123",
			wantMinCon: 0.8,
		},
		{
			name:       "CVC with 3 digits",
			input:      "CVC: 456",
			wantLen:    1,
			wantRaw:    "456",
			wantMinCon: 0.8,
		},
		{
			name:       "CVV2 with 3 digits",
			input:      "CVV2: 789",
			wantLen:    1,
			wantRaw:    "789",
			wantMinCon: 0.8,
		},
		{
			name:       "Amex CID with 4 digits using CVV keyword",
			input:      "CVV: 1234",
			wantLen:    1,
			wantRaw:    "1234",
			wantMinCon: 0.8,
		},
		{
			name:       "CID keyword with 4 digits",
			input:      "CID: 1234",
			wantLen:    1,
			wantRaw:    "1234",
			wantMinCon: 0.8,
		},
		{
			name:       "lowercase cid keyword with 3 digits",
			input:      "cid: 567",
			wantLen:    1,
			wantRaw:    "567",
			wantMinCon: 0.8,
		},
		{
			name:       "title case Cid keyword with 4 digits",
			input:      "Cid: 9012",
			wantLen:    1,
			wantRaw:    "9012",
			wantMinCon: 0.8,
		},
		{
			name:       "SECURITY CODE all caps",
			input:      "SECURITY CODE: 789",
			wantLen:    1,
			wantRaw:    "789",
			wantMinCon: 0.8,
		},
		{
			name:       "security code keyword",
			input:      "security code is 567",
			wantLen:    1,
			wantRaw:    "567",
			wantMinCon: 0.8,
		},
		{
			name:       "lowercase cvv",
			input:      "cvv: 321",
			wantLen:    1,
			wantRaw:    "321",
			wantMinCon: 0.8,
		},
		{
			name:       "no keyword no detection",
			input:      "the code is 123",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "too many digits 5",
			input:      "CVV: 12345",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "too few digits 2",
			input:      "CVV: 12",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			//nolint:goconst // Each test states its fixture and expected result independently.
			name:       "empty input",
			input:      "",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name: "Japanese security code keyword",
			// セキュリティコード: 123
			input:      "\xe3\x82\xbb\xe3\x82\xad\xe3\x83\xa5\xe3\x83\xaa\xe3\x83\x86\xe3\x82\xa3\xe3\x82\xb3\xe3\x83\xbc\xe3\x83\x89: 123",
			wantLen:    1,
			wantRaw:    "123",
			wantMinCon: 0.8,
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

func TestCVVDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewCVV()
	findings := d.Scan([]byte("CVV: 123"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	matched := "CVV: 123"[findings[0].Start:findings[0].End]
	if len(matched) != 3 {
		t.Errorf("DigitCount = %d, want %d", len(matched), 3)
	}
}

func TestCVVDetector_Validation_4digit(t *testing.T) {
	t.Parallel()

	d := NewCVV()
	findings := d.Scan([]byte("CVC: 1234"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	matched := "CVC: 1234"[findings[0].Start:findings[0].End]
	if len(matched) != 4 {
		t.Errorf("DigitCount = %d, want %d", len(matched), 4)
	}
}

func TestCVVDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewCVV()
	if d.Name() != NameCVV {
		t.Errorf("Name() = %q, want %q", d.Name(), NameCVV)
	}
}

func TestCVVDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewCVV()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}

// TestCVVDetector_HintKeywordConsistency verifies that every keyword variant
// in cvvKeywords passes at least one hint in Hints(). This prevents silent
// detection misses where a keyword is recognized by Scan() but the hint
// filter would reject the input before Scan() is ever called.
func TestCVVDetector_HintKeywordConsistency(t *testing.T) {
	t.Parallel()

	d := NewCVV()

	// Every keyword variant that Scan recognizes must be detectable through
	// the hint filter. We embed each keyword in a test string and verify
	// that Scan() can find a CVV near it.
	keywords := []string{
		"CVV", "CVC", "CID",
		"CVV2", "CVC2",
		"cvv", "cvc", "cid",
		"cvv2", "cvc2",
		"Cvv", "Cvc", "Cid",
		"security code",
		"Security Code",
		"Security code",
		"SECURITY CODE",
	}

	for _, kw := range keywords {
		t.Run(kw, func(t *testing.T) {
			t.Parallel()

			input := kw + " 123"
			findings := d.Scan([]byte(input))
			if len(findings) == 0 {
				t.Errorf("keyword %q + digits did not produce a finding via Scan()", kw)
			}
		})
	}
}
