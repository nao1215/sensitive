package detect

import (
	"strings"
	"testing"
)

func TestBankAccountDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewBankAccount()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
		wantMaxCon float64
	}{
		{
			name:       "english keyword with digits",
			input:      "bank account 12345678",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.50,
			wantMaxCon: 0.50,
		},
		{
			name:       "holder context increases confidence",
			input:      "account number 12345678 holder John",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.65,
			wantMaxCon: 0.65,
		},
		{
			name:       "holder keyword far away does not boost confidence",
			input:      "bank account 12345678" + strings.Repeat(" ", 200) + "holder John",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.50,
			wantMaxCon: 0.50,
		},
		{
			name:    "too short digits",
			input:   "bank account 123",
			wantLen: 0,
		},
		{
			name:    noKeywordCase,
			input:   "12345678",
			wantLen: 0,
		},
		{
			name:       "full-width digits with japanese keyword",
			input:      "口座番号 １２３４５６７８",
			wantLen:    1,
			wantRaw:    "１２３４５６７８",
			wantMinCon: 0.50,
			wantMaxCon: 0.50,
		},
		{
			name:       "full-width digits with holder name context",
			input:      "口座番号 １２３４５６７８ 名義人 田中太郎",
			wantLen:    1,
			wantRaw:    "１２３４５６７８",
			wantMinCon: 0.65,
			wantMaxCon: 0.65,
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
			if f.Confidence < tt.wantMinCon || f.Confidence > tt.wantMaxCon {
				t.Errorf("Confidence = %f, want within [%f, %f]", f.Confidence, tt.wantMinCon, tt.wantMaxCon)
			}
		})
	}
}

func TestBankAccountDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewBankAccount()
	if d.Name() != NameBankAccount {
		t.Errorf("Name() = %q, want %q", d.Name(), NameBankAccount)
	}
}

func TestBankAccountDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewBankAccount()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}

func TestBankAccountKeywordLanguages(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"bank account 12345678", "口座番号 12345678"} {
		got := NewBankAccount().Scan([]byte(text))
		if len(got) != 1 || got[0].End != len(text) || text[got[0].Start:got[0].End] != "12345678" {
			t.Fatal(text, got)
		}
	}
}
