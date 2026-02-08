package detector

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
		wantLen    int
		wantRaw    string
		wantMinCon float64
		wantMaxCon float64
		wantLang   BankAccountLanguage
	}{
		{
			name:       "english keyword with digits",
			input:      "bank account 12345678",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.50,
			wantMaxCon: 0.50,
			wantLang:   BankAccountLangEN,
		},
		{
			name:       "holder context increases confidence",
			input:      "account number 12345678 holder John",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.65,
			wantMaxCon: 0.65,
			wantLang:   BankAccountLangEN,
		},
		{
			name:       "holder keyword far away does not boost confidence",
			input:      "bank account 12345678" + strings.Repeat(" ", 200) + "holder John",
			wantLen:    1,
			wantRaw:    "12345678",
			wantMinCon: 0.50,
			wantMaxCon: 0.50,
			wantLang:   BankAccountLangEN,
		},
		{
			name:    "too short digits",
			input:   "bank account 123",
			wantLen: 0,
		},
		{
			name:    "no keyword",
			input:   "12345678",
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
			if f.Confidence < tt.wantMinCon || f.Confidence > tt.wantMaxCon {
				t.Errorf("Confidence = %f, want within [%f, %f]", f.Confidence, tt.wantMinCon, tt.wantMaxCon)
			}

			if detail, ok := f.BankAccountDetail(); ok {
				if detail.Language != tt.wantLang {
					t.Errorf("Language = %q, want %q", detail.Language, tt.wantLang)
				}
				if detail.ContextKeyword == "" {
					t.Error("ContextKeyword is empty")
				}
			} else {
				t.Error("BankAccountDetail() returned false")
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

func TestBankAccountKeywordLang(t *testing.T) {
	t.Parallel()

	if got := bankAccountKeywordLang([]byte("bank account")); got != BankAccountLangEN {
		t.Errorf("bankAccountKeywordLang(en) = %q, want %q", got, BankAccountLangEN)
	}
	if got := bankAccountKeywordLang([]byte("口座番号")); got != BankAccountLangJA {
		t.Errorf("bankAccountKeywordLang(ja) = %q, want %q", got, BankAccountLangJA)
	}
}

func TestContainsBytes(t *testing.T) {
	t.Parallel()

	if !containsBytes([]byte("abc"), []byte("")) {
		t.Error("containsBytes should return true for empty sub")
	}
	if containsBytes([]byte("ab"), []byte("abc")) {
		t.Error("containsBytes should return false when sub is longer than data")
	}
	if !containsBytes([]byte("abc"), []byte("bc")) {
		t.Error("containsBytes should find existing substring")
	}
}

func TestContainsAnyNear(t *testing.T) {
	t.Parallel()

	data := []byte("account number 12345678 holder John")
	keywords := [][]byte{[]byte("holder")}

	// "holder" starts at byte 24, digit sequence "12345678" is at [15,23).
	// Within radius 50 of region [15,23) → should be found.
	if !containsAnyNear(data, 15, 23, 50, keywords) {
		t.Error("containsAnyNear should find 'holder' within radius 50 of digit sequence")
	}

	// With a very small radius (1 byte), "holder" is too far away.
	if containsAnyNear(data, 15, 23, 1, keywords) {
		t.Error("containsAnyNear should not find 'holder' within radius 1 of digit sequence")
	}

	// Keyword far away in a long string.
	farData := []byte("account number 12345678" + strings.Repeat(" ", 200) + "holder")
	if containsAnyNear(farData, 15, 23, 50, keywords) {
		t.Error("containsAnyNear should not find 'holder' when it is 200+ bytes away")
	}
}

func TestContainsAny(t *testing.T) {
	t.Parallel()

	data := []byte("routing number")
	keywords := [][]byte{[]byte("iban"), []byte("routing")}
	if !containsAny(data, keywords) {
		t.Error("containsAny should return true when any keyword matches")
	}
	if containsAny([]byte("nothing here"), keywords) {
		t.Error("containsAny should return false when no keyword matches")
	}
}
