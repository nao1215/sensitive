package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestABARoutingDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewABARouting()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
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
			name:       "empty input",
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

func TestABARoutingDetector_ChecksumFailedAlwaysRejected(t *testing.T) {
	t.Parallel()

	d := detector.NewABARouting()
	// Even with routing context keyword, checksum failure must be rejected.
	findings := d.Scan([]byte("routing: 611070545"))
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (checksum failure must always be rejected)", len(findings))
	}
}

func TestABARoutingDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewABARouting()
	findings := d.Scan([]byte("routing: 021000021"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	detail, ok := findings[0].ABARoutingDetail()
	if !ok {
		t.Fatal("ABARoutingDetail() returned false")
	}
	if detail.FederalReserveDistrict != "02-New York" {
		t.Errorf("FederalReserveDistrict = %q, want %q", detail.FederalReserveDistrict, "02-New York")
	}
}

func TestABARoutingDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewABARouting()
	if d.Name() != detector.NameABARouting {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameABARouting)
	}
}

func TestABARoutingDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewABARouting()
	if d.Hints() != nil {
		t.Errorf("Hints() = %v, want nil", d.Hints())
	}
}
