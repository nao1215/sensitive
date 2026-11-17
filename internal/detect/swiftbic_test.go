package detect

import (
	"fmt"
	"strings"
	"testing"
)

const swiftWireFixture = "wire to HSBCHKHH"

func TestSWIFTContextDoesNotConsumeNeighboringWords(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"wireless DEUTDEFF", "DEUTDEFF swiftcompiler", "bicycle DEUTDEFF"} {
		if got := NewSWIFTBIC().Scan([]byte(input)); len(got) != 0 {
			t.Errorf("unrelated context %q: %+v", input, got)
		}
	}
	for _, input := range []string{"syscall=59 account=fefbAE01", "syscall=59 a0=BOFAUS3N"} {
		if got := NewSWIFTBIC().Scan([]byte(input)); len(got) != 1 {
			t.Errorf("register exclusion too broad %q: %+v", input, got)
		}
	}
	input := "SWIFT: DEUTDEFF/HSBCHKHH/BNPAFRPP"
	if got := NewSWIFTBIC().Scan([]byte(input)); len(got) != 3 {
		t.Errorf("slash list lost later codes: %+v", got)
	}
}

func TestSWIFTBICDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewSWIFTBIC()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "Deutsche Bank 8-char SWIFT code with digit in location",
			input:      "SWIFT code: DEUTDEFF",
			wantLen:    1,
			wantRaw:    "DEUTDEFF",
			wantMinCon: 0.8,
		},
		{
			name:       "Bank of America 11-char SWIFT code with digit",
			input:      "BIC: BOFAUS3NXXX",
			wantLen:    1,
			wantRaw:    "BOFAUS3NXXX",
			wantMinCon: 0.8,
		},
		{
			name:       "HSBC Hong Kong with digit in location",
			input:      swiftWireFixture,
			wantLen:    1,
			wantRaw:    "HSBCHKHH",
			wantMinCon: 0.8,
		},
		{
			name:       "11-char code with branch digits",
			input:      "BIC COBADEFF100",
			wantLen:    1,
			wantRaw:    "COBADEFF100",
			wantMinCon: 0.8,
		},
		{
			name:       "lowercase SWIFT code with digit in location",
			input:      "swift: deutdeff",
			wantLen:    1,
			wantRaw:    "deutdeff",
			wantMinCon: 0.8,
		},
		{
			name:       "pure alpha code with SWIFT context keyword",
			input:      "SWIFT: BNPAFRPP",
			wantLen:    1,
			wantRaw:    "BNPAFRPP",
			wantMinCon: 0.8,
		},
		{
			name:       "pure alpha code without context keyword is skipped",
			input:      "the word BNPAFRPP appears here",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "too short 7 chars",
			input:      "SWIFT: DEUTDEF",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "9 chars invalid SWIFT length",
			input:      "code DEUTDEFF1 here",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "10 chars invalid SWIFT length",
			input:      "code DEUTDEFF10 here",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "invalid country code",
			input:      "code DEUTXXFF here",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "bank code not all alpha",
			input:      "code D3UTDEFF here",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "part of longer word is not matched",
			input:      "XDEUTDEFF",
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
			name:       "multiple SWIFT codes in one line",
			input:      "SWIFT: DEUTDE5F and BIC: BOFAUS3N",
			wantLen:    2,
			wantRaw:    "",
			wantMinCon: 0.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assertScanCase(t, d, tt.input, tt.wantLen, tt.wantRaw, tt.wantMinCon)
		})
	}
}

func TestSWIFTBICDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewSWIFTBIC()
	findings := d.Scan([]byte("BIC: BOFAUS3NXXX"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	matched := "BIC: BOFAUS3NXXX"[findings[0].Start:findings[0].End]
	if matched[:4] != "BOFA" {
		t.Errorf("BankCode = %q, want %q", matched[:4], "BOFA")
	}
	if matched[4:6] != "US" {
		t.Errorf("CountryCode = %q, want %q", matched[4:6], "US")
	}
	if matched[6:8] != "3N" {
		t.Errorf("LocationCode = %q, want %q", matched[6:8], "3N")
	}
	if matched[8:] != "XXX" {
		t.Errorf("BranchCode = %q, want %q", matched[8:], "XXX")
	}
}

func TestSWIFTBICDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewSWIFTBIC()
	if d.Name() != NameSWIFTBIC {
		t.Errorf("Name() = %q, want %q", d.Name(), NameSWIFTBIC)
	}
}

func TestSWIFTBICDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewSWIFTBIC()
	if d.Hints() != nil {
		t.Errorf("Hints() = %v, want nil", d.Hints())
	}
}

func TestSWIFTSlashListAndSourcePath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want int
	}{
		{"swift=DEUTDEFF/COBADEFF", 2},
		{"DEUTDEFF/COBADEFF swift", 2},
		{"BIC: DEUTDEFF/COBADEFF/CHASUS33", 3},
		{"swift source=/tmp/COBADEFF", 0},
		{"swift source=DEUTDEFF.log", 0},
		{"swift source=/DEUTDEFF", 0},
		{"swift source=DEUTDEFF/tmp", 0},
		{"swift source=DEUTDEFF/NOTACODE99", 0},
		{"swift source=DEUTDEFF/COBADEFF01", 0},
		{"swift source=NOTACODE99/DEUTDEFF", 0},
	} {
		if got := NewSWIFTBIC().Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("SWIFT list versus source path %q: %v", tc.text, got)
		}
	}
}

func TestSWIFTZCountryCodes(t *testing.T) {
	t.Parallel()
	for _, country := range []string{"ZA", "ZM", "ZW", "ZZ"} {
		raw := "BANK" + country + "12"
		findings := NewSWIFTBIC().Scan([]byte("SWIFT: " + raw))
		if country == "ZZ" {
			if len(findings) != 0 {
				t.Fatal("unsupported country accepted")
			}
			continue
		}
		if len(findings) != 1 || ("SWIFT: " + raw)[findings[0].Start:findings[0].End] != raw || findings[0].Start != len("SWIFT: ") || findings[0].End != len("SWIFT: ")+len(raw) {
			t.Fatalf("valid country %s lost or mislocated: %+v", country, findings)
		}
	}
}

func TestSWIFTBuildLanguageContexts(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"swift package resolved", "swift package RESOLVED", "swift package Resolved", "swift dependencies resolved"} {
		if got := NewSWIFTBIC().Scan([]byte(text)); len(got) != 0 {
			t.Errorf("build output treated as BIC: %s", text)
		}
	}
}

func TestSWIFTLanguageWordShapeProperty(t *testing.T) {
	t.Parallel()
	for _, bank := range []string{"TEST", "RESO", "ABCD"} {
		for _, country := range []string{"LV", "US", "GB", "JP"} {
			for _, location := range []string{"ED", "AB", "XY"} {
				word := bank + country + location
				for _, phrase := range []string{"swift package ", "swift dependencies ", "swift source "} {
					if got := NewSWIFTBIC().Scan([]byte(phrase + word)); len(got) != 0 {
						t.Fatalf("language context admitted word shape: %s%s", phrase, word)
					}
				}
				if got := NewSWIFTBIC().Scan([]byte("SWIFT: " + word)); len(got) != 1 {
					t.Fatal("explicit bank context lost")
				}
			}
		}
	}
}

func TestSWIFTRegisterProperty(t *testing.T) {
	t.Parallel()
	assertSWIFTContextProperty(t, func(code string) string { return "syscall=42 a0=" + code })
}

func TestSWIFTUserSlotProperty(t *testing.T) {
	t.Parallel()
	assertSWIFTContextProperty(t, func(code string) string { return "Invalid user " + code + " from host" })
}

func TestSWIFTIdentifierProperty(t *testing.T) {
	t.Parallel()
	assertSWIFTContextProperty(t, func(code string) string { return "input_" + code + "_request swift" })
}

func TestSWIFTHardwareWireProperty(t *testing.T) {
	t.Parallel()
	assertSWIFTContextProperty(t, func(code string) string { return "warning for node wire, " + code })
}

func TestSWIFTKeySpellingProperty(t *testing.T) {
	t.Parallel()
	d := NewSWIFTBIC()
	for n := range 26 {
		code := string(rune('A'+n)) + "BCDDEFF"
		for _, key := range []string{"SWIFT-Code:", "swift_code=", "swiftCode=", "SWIFTCODE:", "SWIFT number", "SWIFT No.", "SWIFT address", "Swift/BIC:", "swift_bic=", "swift ("} {
			input := key + " " + code
			if got := d.Scan([]byte(input)); len(got) != 1 || input[got[0].Start:got[0].End] != code {
				t.Errorf("%q: %+v", input, got)
			}
		}
		for _, word := range []string{"package", "dependency", "source", "compiler"} {
			input := "swift " + word + " " + code
			for _, got := range d.Scan([]byte(input)) {
				if input[got.Start:got.End] == code {
					t.Errorf("build context %q: %+v", input, got)
				}
			}
		}
	}
}

// assertSWIFTContextProperty checks 100 BIC-shaped codes: each is rejected in
// the excluded context built by excluded and still found in positive contexts.
func assertSWIFTContextProperty(t *testing.T, excluded func(code string) string) {
	t.Helper()
	d := NewSWIFTBIC()
	for n := range 100 {
		code := fmt.Sprintf("fefbAE%02x", n)
		if got := d.Scan([]byte(excluded(code))); len(got) != 0 {
			t.Errorf("context accepted: %s: %+v", code, got)
		}
		for _, positive := range []string{"BIC: " + code, swiftWireFixture, "swift " + strings.ToLower(code)} {
			if got := d.Scan([]byte(positive)); len(got) != 1 {
				t.Errorf("positive lost: %s: %+v", positive, got)
			}
		}
	}
}
