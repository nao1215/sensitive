package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestMerchantIDDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewMerchantID()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
		wantMinCon float64
		wantIDType detector.MerchantIDType
	}{
		{
			name:       "merchant ID",
			input:      "merchant ID ABCDE12345FGHI6",
			wantLen:    1,
			wantRaw:    "ABCDE12345FGHI6",
			wantMinCon: 0.7,
			wantIDType: detector.MerchantIDTypeMerchant,
		},
		{
			name:       "terminal ID",
			input:      "TID 12345678",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.7,
			wantIDType: detector.MerchantIDTypeTerminal,
		},
		{
			name:    "no keyword",
			input:   "ABCDE12345FGHI6",
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
			f := findings[0]
			if tt.wantRaw != "" && f.RawValue != tt.wantRaw {
				t.Errorf("RawValue = %q, want %q", f.RawValue, tt.wantRaw)
			}
			if f.Confidence < tt.wantMinCon {
				t.Errorf("Confidence = %f, want >= %f", f.Confidence, tt.wantMinCon)
			}

			detail, ok := f.MerchantIDDetail()
			if !ok {
				t.Fatal("MerchantIDDetail() returned false")
			}
			if detail.IDType != tt.wantIDType {
				t.Errorf("IDType = %q, want %q", detail.IDType, tt.wantIDType)
			}
		})
	}
}

func TestMerchantIDDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewMerchantID()
	if d.Name() != detector.NameMerchantID {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameMerchantID)
	}
}

func TestMerchantIDDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewMerchantID()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}
