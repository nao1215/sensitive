package detect

import (
	"testing"
)

func TestMerchantIDDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewMerchantID()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "merchant ID",
			input:      "merchant ID ABCDE12345FGHI6",
			wantLen:    1,
			wantRaw:    "ABCDE12345FGHI6",
			wantMinCon: 0.7,
		},
		{
			name:       "terminal ID",
			input:      "TID 12345678",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.7,
		},
		{
			name:       "repeated terminal keywords do not duplicate a finding",
			input:      "TID terminal ID 12345678",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.7,
		},
		{
			name:       "digits inside a merchant ID are not reported again as a terminal ID",
			input:      "Merchant ID A00000000A00000 TID 000",
			wantLen:    1,
			wantRaw:    "A00000000A00000",
			wantMinCon: 0.7,
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
			if tt.wantRaw != "" && tt.input[f.Start:f.End] != tt.wantRaw {
				t.Errorf("matched text = %q, want %q", tt.input[f.Start:f.End], tt.wantRaw)
			}
			if f.Confidence < tt.wantMinCon {
				t.Errorf("Confidence = %f, want >= %f", f.Confidence, tt.wantMinCon)
			}
		})
	}
}

func TestMerchantIDDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewMerchantID()
	if d.Name() != NameMerchantID {
		t.Errorf("Name() = %q, want %q", d.Name(), NameMerchantID)
	}
}

func TestMerchantIDDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewMerchantID()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}
