package detect

import (
	"testing"
)

func TestJPPhoneDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "mobile with dashes",
			input:      "call 090-1234-5678 now",
			wantLen:    1,
			wantRaw:    sampleMobile,
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
			wantRaw:    sampleLandline,
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
			name: "IP phone",
			//nolint:goconst // Each test states its fixture and expected result independently.
			input:      "050-1234-5678",
			wantLen:    1,
			wantRaw:    "050-1234-5678",
			wantMinCon: 0.8,
		},
		{
			name: "toll-free 0120",
			//nolint:goconst // Each test states its fixture and expected result independently.
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
			name:    emptyInputCase,
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

			assertDetectorScan(t, d, tt.input, tt.wantLen, tt.wantRaw, tt.wantMinCon)
		})
	}
}

func TestJPPhoneDetector_FullWidthSpan(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	input := "TEL: ０９０－１２３４－５６７８"
	findings := d.Scan([]byte(input))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	want := "０９０－１２３４－５６７８"
	if input[f.Start:f.End] != want {
		t.Errorf("matched text = %q, want %q", input[f.Start:f.End], want)
	}
}

func TestJPPhoneDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	tests := []struct {
		input    string
		wantType JPPhoneType
	}{
		{input: sampleMobile, wantType: JPPhoneTypeMobile},
		{input: sampleLandline, wantType: JPPhoneTypeLandline},
		{input: "050-1234-5678", wantType: JPPhoneTypeIPPhone},
		{input: "0120-123-456", wantType: JPPhoneTypeTollFree},
		{input: "020-1234-5678", wantType: JPPhoneTypeM2M},
		{input: "060-1234-5678", wantType: JPPhoneTypeService},
	}
	for _, tt := range tests {
		findings := d.Scan([]byte(tt.input))
		if len(findings) != 1 {
			t.Fatalf("input=%q: got %d findings, want 1", tt.input, len(findings))
		}
		digits := testDigits([]byte(tt.input[findings[0].Start:findings[0].End]))
		if classifyJPPhone(digits, len(digits)) != tt.wantType {
			t.Errorf("input=%q: PhoneType = %q, want %q", tt.input, classifyJPPhone(digits, len(digits)), tt.wantType)
		}
	}
}

func TestJPPhoneDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	if d.Name() != NameJPPhone {
		t.Errorf("Name() = %q, want %q", d.Name(), NameJPPhone)
	}
}

func TestJPPhoneDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	hints := d.Hints()
	if len(hints) != 3 || string(hints[2]) != "+81" {
		t.Fatalf("Hints() = %q, want 0, full-width zero and +81", hints)
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

	d := NewJPPhone()
	// '0' preceded by alphanumeric should be skipped.
	findings := d.Scan([]byte("x09012345678"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for alpha-preceded phone, want 0", len(findings))
	}
}

func TestJPPhoneDetector_FollowedByAlpha(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	// Phone number followed by alphanumeric should not match.
	findings := d.Scan([]byte("09012345678x"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for phone followed by alpha, want 0", len(findings))
	}
}

func TestJPPhoneDetector_WithParentheses(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	findings := d.Scan([]byte("03(1234)5678"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if "03(1234)5678"[findings[0].Start:findings[0].End] != "03(1234)5678" {
		t.Errorf("matched text = %q, want %q", "03(1234)5678"[findings[0].Start:findings[0].End], "03(1234)5678")
	}
}

func TestJPPhoneDetector_Landline080Prefix(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	// 080 as 11-digit is mobile.
	findings := d.Scan([]byte("080-1234-5678"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	digits := testDigits([]byte("080-1234-5678"[findings[0].Start:findings[0].End]))
	if classifyJPPhone(digits, len(digits)) != JPPhoneTypeMobile {
		t.Errorf("PhoneType = %q, want %q", classifyJPPhone(digits, len(digits)), JPPhoneTypeMobile)
	}
}

func TestJPPhoneDetector_070Mobile(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	findings := d.Scan([]byte("070-1234-5678"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	digits := testDigits([]byte("070-1234-5678"[findings[0].Start:findings[0].End]))
	if classifyJPPhone(digits, len(digits)) != JPPhoneTypeMobile {
		t.Errorf("PhoneType = %q, want %q", classifyJPPhone(digits, len(digits)), JPPhoneTypeMobile)
	}
}

func TestJPPhoneDetector_0800Classified(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	// 0800 (11 digits) matches the 080 mobile prefix check first.
	findings := d.Scan([]byte("0800-123-4567"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	digits := testDigits([]byte("0800-123-4567"[findings[0].Start:findings[0].End]))
	if classifyJPPhone(digits, len(digits)) != JPPhoneTypeMobile {
		t.Errorf("PhoneType = %q, want %q", classifyJPPhone(digits, len(digits)), JPPhoneTypeMobile)
	}
}

func TestJPPhoneDetector_LandlineValid(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	// 06 (Osaka) should be a valid landline prefix.
	findings := d.Scan([]byte("06-1234-5678"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	digits := testDigits([]byte("06-1234-5678"[findings[0].Start:findings[0].End]))
	if classifyJPPhone(digits, len(digits)) != JPPhoneTypeLandline {
		t.Errorf("PhoneType = %q, want %q", classifyJPPhone(digits, len(digits)), JPPhoneTypeLandline)
	}
}

func TestJPPhoneDetector_TooManyDigits(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	// 12 digits should not match.
	findings := d.Scan([]byte("090123456789"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for 12 digits, want 0", len(findings))
	}
}

func TestJPPhoneDetector_ShortDigits(t *testing.T) {
	t.Parallel()

	d := NewJPPhone()
	// 9 digits should not match.
	findings := d.Scan([]byte("090-123-456"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for 9 digits, want 0", len(findings))
	}
}

func TestPhoneConfidenceAndContainsEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw        string
		confidence float64
	}{{sampleMobile, .9}, {sampleLandline, .8}} {
		got := NewJPPhone().Scan([]byte(tc.raw))
		if len(got) != 1 || got[0].Confidence != tc.confidence {
			t.Fatal(tc.raw, got)
		}
	}
}

func TestPhoneJpRejectedBoundaries(t *testing.T) {
	t.Parallel()
	if classifyJPPhone(nil, 0) != "" || isValidLandlinePrefix(nil) {
		t.Fatal("short phone accepted")
	}
}

func TestJPPhoneDetector_InternationalForm(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ input, want string }{
		{"tel +81-90-1234-5678", "+81-90-1234-5678"},
		{"+819012345678", "+819012345678"},
		{"call +81 (0)3-1234-5678 now", "+81 (0)3-1234-5678"},
		{"+81 3 1234 5678", "+81 3 1234 5678"},
		{"tel:+81-120-123-456.", "+81-120-123-456"},
		{"x+819012345678", ""},
		{"+81-12", ""},
		{"+8190123456789", ""},
		{"+81", ""},
		{"+1-202-555-0143", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := ""
			if findings := NewJPPhone().Scan([]byte(tc.input)); len(findings) == 1 {
				got = tc.input[findings[0].Start:findings[0].End]
			} else if len(findings) > 1 {
				t.Fatalf("findings %+v", findings)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJPPhoneInternationalNearMisses(t *testing.T) {
	t.Parallel()
	d := NewJPPhone()
	for _, input := range []string{"+81 x", "+81-12", "+81-90", "+8112345678901234", "+81 1234567890"} {
		data := []byte(input)
		if _, next, ok := d.international(data, data, nil, 0); ok || next <= 0 {
			t.Errorf("international(%q) = ok %v next %d", input, ok, next)
		}
	}
}

const parenthesizedLandline = "(03)1234-5678"

func TestJPPhoneParenthesizedAreaCode(t *testing.T) {
	t.Parallel()
	d := NewJPPhone()
	for input, want := range map[string]string{
		"tel (03)1234-5678":   parenthesizedLandline,
		parenthesizedLandline: parenthesizedLandline,
		"tel 03(1234)5678":    "03(1234)5678",
		"tel (03-1234-5678":   "03-1234-5678",
		"tel ((03)1234-5678)": parenthesizedLandline,
	} {
		findings := d.Scan([]byte(input))
		if len(findings) != 1 || input[findings[0].Start:findings[0].End] != want {
			t.Errorf("Scan(%q) = %+v, want %q", input, findings, want)
		}
	}
}
