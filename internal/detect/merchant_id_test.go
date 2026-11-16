package detect_test

import (
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

func TestMerchantIDDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detect.NewMerchantID()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantIDType detect.MerchantIDType
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "merchant ID",
			input:      "merchant ID ABCDE12345FGHI6",
			wantLen:    1,
			wantRaw:    "ABCDE12345FGHI6",
			wantMinCon: 0.7,
			wantIDType: detect.MerchantIDTypeMerchant,
		},
		{
			name:       "terminal ID",
			input:      "TID 12345678",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.7,
			wantIDType: detect.MerchantIDTypeTerminal,
		},
		{
			name:       "repeated terminal keywords do not duplicate a finding",
			input:      "TID terminal ID 12345678",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.7,
			wantIDType: detect.MerchantIDTypeTerminal,
		},
		{
			name:       "digits inside a merchant ID are not reported again as a terminal ID",
			input:      "Merchant ID A00000000A00000 TID 000",
			wantLen:    1,
			wantRaw:    "A00000000A00000",
			wantMinCon: 0.7,
			wantIDType: detect.MerchantIDTypeMerchant,
		},
		{
			name:    "terminal digits inside an alphanumeric token",
			input:   "TID 12345678merchant ID ABCDE12345FGHI6",
			wantLen: 0,
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

	d := detect.NewMerchantID()
	if d.Name() != detect.NameMerchantID {
		t.Errorf("Name() = %q, want %q", d.Name(), detect.NameMerchantID)
	}
}

func TestMerchantIDDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detect.NewMerchantID()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}
