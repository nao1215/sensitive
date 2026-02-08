package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestJPPhoneDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
		wantMinCon float64
	}{
		{
			name:       "mobile with dashes",
			input:      "call 090-1234-5678 now",
			wantLen:    1,
			wantRaw:    "090-1234-5678",
			wantMinCon: 0.8,
		},
		{
			name:       "mobile no separator",
			input:      "phone: 09012345678",
			wantLen:    1,
			wantRaw:    "09012345678",
			wantMinCon: 0.8,
		},
		{
			name:       "landline Tokyo",
			input:      "TEL: 03-1234-5678",
			wantLen:    1,
			wantRaw:    "03-1234-5678",
			wantMinCon: 0.8,
		},
		{
			name:       "landline no separator",
			input:      "0312345678",
			wantLen:    1,
			wantRaw:    "0312345678",
			wantMinCon: 0.8,
		},
		{
			name:       "IP phone",
			input:      "050-1234-5678",
			wantLen:    1,
			wantRaw:    "050-1234-5678",
			wantMinCon: 0.8,
		},
		{
			name:       "toll-free 0120",
			input:      "0120-123-456",
			wantLen:    1,
			wantRaw:    "0120-123-456",
			wantMinCon: 0.8,
		},
		{
			name:       "toll-free 0800",
			input:      "0800-123-4567",
			wantLen:    1,
			wantRaw:    "0800-123-4567",
			wantMinCon: 0.8,
		},

		// False positives
		{
			name:    "too few digits",
			input:   "012-345-678",
			wantLen: 0,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "no phone numbers",
			input:   "hello world",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 0501 (10 digits)",
			input:   "0501234567",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 0701 (10 digits)",
			input:   "0701234567",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 0901 (10 digits)",
			input:   "0901234567",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 0571 (10 digits)",
			input:   "0571234567",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 0511 (10 digits)",
			input:   "0511234567",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 0711 (10 digits)",
			input:   "0711234567",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 0811 (10 digits)",
			input:   "0811234567",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 0911 (10 digits)",
			input:   "0911234567",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 020 (10 digits)",
			input:   "0201234567",
			wantLen: 0,
		},
		{
			name:    "invalid prefix 021 (10 digits)",
			input:   "0211234567",
			wantLen: 0,
		},

		// Space-separated formats.
		{
			name:       "mobile with spaces",
			input:      "call 090 1234 5678 now",
			wantLen:    1,
			wantRaw:    "090 1234 5678",
			wantMinCon: 0.8,
		},
		{
			name:       "landline with spaces",
			input:      "TEL: 03 1234 5678",
			wantLen:    1,
			wantRaw:    "03 1234 5678",
			wantMinCon: 0.8,
		},

		// Underscore boundary.
		{
			name:    "preceded by underscore",
			input:   "_09012345678",
			wantLen: 0,
		},
		{
			name:    "followed by underscore",
			input:   "09012345678_",
			wantLen: 0,
		},
		{
			name:    "preceded by underscore with dashes",
			input:   "_090-1234-5678",
			wantLen: 0,
		},
		{
			name:    "followed by underscore with dashes",
			input:   "090-1234-5678_",
			wantLen: 0,
		},

		// 020 and 060 prefixes.
		{
			name:       "M2M/IoT 020 prefix",
			input:      "device 020-1234-5678",
			wantLen:    1,
			wantRaw:    "020-1234-5678",
			wantMinCon: 0.8,
		},
		{
			name:       "service 060 prefix",
			input:      "call 060-1234-5678",
			wantLen:    1,
			wantRaw:    "060-1234-5678",
			wantMinCon: 0.8,
		},
		{
			name:    "invalid prefix 060 (10 digits)",
			input:   "0601234567",
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

func TestJPPhoneDetector_FullWidthRawValue(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	input := "TEL: ０９０－１２３４－５６７８"
	findings := d.Scan([]byte(input))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	want := "０９０－１２３４－５６７８"
	if f.RawValue != want {
		t.Errorf("RawValue = %q, want %q", f.RawValue, want)
	}
	if input[f.Start:f.End] != f.RawValue {
		t.Errorf("input[Start:End] = %q, RawValue = %q", input[f.Start:f.End], f.RawValue)
	}
}

func TestJPPhoneDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	tests := []struct {
		input    string
		wantType detector.JPPhoneType
	}{
		{"090-1234-5678", detector.JPPhoneTypeMobile},
		{"03-1234-5678", detector.JPPhoneTypeLandline},
		{"050-1234-5678", detector.JPPhoneTypeIPPhone},
		{"0120-123-456", detector.JPPhoneTypeTollFree},
		{"020-1234-5678", detector.JPPhoneTypeM2M},
		{"060-1234-5678", detector.JPPhoneTypeService},
	}
	for _, tt := range tests {
		findings := d.Scan([]byte(tt.input))
		if len(findings) != 1 {
			t.Fatalf("input=%q: got %d findings, want 1", tt.input, len(findings))
		}
		detail, ok := findings[0].JPPhoneDetail()
		if !ok {
			t.Fatalf("input=%q: JPPhoneDetail() returned false", tt.input)
		}
		if detail.PhoneType != tt.wantType {
			t.Errorf("input=%q: PhoneType = %q, want %q", tt.input, detail.PhoneType, tt.wantType)
		}
	}
}

func TestJPPhoneDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	if d.Name() != detector.NameJPPhone {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameJPPhone)
	}
}

func TestJPPhoneDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	hints := d.Hints()
	if len(hints) != 2 {
		t.Fatalf("Hints() returned %d hints, want 2", len(hints))
	}
	if string(hints[0]) != "0" {
		t.Errorf("Hints()[0] = %q, want %q", hints[0], "0")
	}
	// hints[1] should be full-width ０ (U+FF10 = 0xEF 0xBC 0x90).
	if len(hints[1]) != 3 || hints[1][0] != 0xEF || hints[1][1] != 0xBC || hints[1][2] != 0x90 {
		t.Errorf("Hints()[1] = %v, want [0xEF 0xBC 0x90] (full-width zero)", hints[1])
	}
}

func TestJPPhoneDetector_PrecededByAlpha(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	// '0' preceded by alphanumeric should be skipped.
	findings := d.Scan([]byte("x09012345678"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for alpha-preceded phone, want 0", len(findings))
	}
}

func TestJPPhoneDetector_FollowedByAlpha(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	// Phone number followed by alphanumeric should not match.
	findings := d.Scan([]byte("09012345678x"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for phone followed by alpha, want 0", len(findings))
	}
}

func TestJPPhoneDetector_WithParentheses(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	findings := d.Scan([]byte("03(1234)5678"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RawValue != "03(1234)5678" {
		t.Errorf("RawValue = %q, want %q", findings[0].RawValue, "03(1234)5678")
	}
}

func TestJPPhoneDetector_Landline080Prefix(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	// 080 as 11-digit is mobile.
	findings := d.Scan([]byte("080-1234-5678"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].JPPhoneDetail()
	if !ok {
		t.Fatal("JPPhoneDetail() returned false")
	}
	if detail.PhoneType != detector.JPPhoneTypeMobile {
		t.Errorf("PhoneType = %q, want %q", detail.PhoneType, detector.JPPhoneTypeMobile)
	}
}

func TestJPPhoneDetector_070Mobile(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	findings := d.Scan([]byte("070-1234-5678"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].JPPhoneDetail()
	if !ok {
		t.Fatal("JPPhoneDetail() returned false")
	}
	if detail.PhoneType != detector.JPPhoneTypeMobile {
		t.Errorf("PhoneType = %q, want %q", detail.PhoneType, detector.JPPhoneTypeMobile)
	}
}

func TestJPPhoneDetector_0800Classified(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	// 0800 (11 digits) matches the 080 mobile prefix check first.
	findings := d.Scan([]byte("0800-123-4567"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].JPPhoneDetail()
	if !ok {
		t.Fatal("JPPhoneDetail() returned false")
	}
	if detail.PhoneType != detector.JPPhoneTypeMobile {
		t.Errorf("PhoneType = %q, want %q", detail.PhoneType, detector.JPPhoneTypeMobile)
	}
}

func TestJPPhoneDetector_LandlineValid(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	// 06 (Osaka) should be a valid landline prefix.
	findings := d.Scan([]byte("06-1234-5678"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].JPPhoneDetail()
	if !ok {
		t.Fatal("JPPhoneDetail() returned false")
	}
	if detail.PhoneType != detector.JPPhoneTypeLandline {
		t.Errorf("PhoneType = %q, want %q", detail.PhoneType, detector.JPPhoneTypeLandline)
	}
}

func TestJPPhoneDetector_TooManyDigits(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	// 12 digits should not match.
	findings := d.Scan([]byte("090123456789"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for 12 digits, want 0", len(findings))
	}
}

func TestJPPhoneDetector_ShortDigits(t *testing.T) {
	t.Parallel()

	d := detector.NewJPPhone()
	// 9 digits should not match.
	findings := d.Scan([]byte("090-123-456"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for 9 digits, want 0", len(findings))
	}
}
