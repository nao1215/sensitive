package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestSWIFTBICDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewSWIFTBIC()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
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
			input:      "wire to HSBCHKHH",
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
			name:       "empty input",
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

func TestSWIFTBICDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewSWIFTBIC()
	findings := d.Scan([]byte("BIC: BOFAUS3NXXX"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	detail, ok := findings[0].SWIFTBICDetail()
	if !ok {
		t.Fatal("SWIFTBICDetail() returned false")
	}
	if detail.BankCode != "BOFA" {
		t.Errorf("BankCode = %q, want %q", detail.BankCode, "BOFA")
	}
	if detail.CountryCode != "US" {
		t.Errorf("CountryCode = %q, want %q", detail.CountryCode, "US")
	}
	if detail.LocationCode != "3N" {
		t.Errorf("LocationCode = %q, want %q", detail.LocationCode, "3N")
	}
	if detail.BranchCode != "XXX" {
		t.Errorf("BranchCode = %q, want %q", detail.BranchCode, "XXX")
	}
}

func TestSWIFTBICDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewSWIFTBIC()
	if d.Name() != detector.NameSWIFTBIC {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameSWIFTBIC)
	}
}

func TestSWIFTBICDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewSWIFTBIC()
	if d.Hints() != nil {
		t.Errorf("Hints() = %v, want nil", d.Hints())
	}
}
