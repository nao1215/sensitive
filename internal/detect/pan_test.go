package detect_test

import (
	"os"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

//nolint:gocognit // Keep each acceptance table and its assertions together for review.
func TestPANDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	tests := []struct {
		name       string
		input      string
		wantBrand  detect.CardBrand
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		// Valid PANs (well-known test numbers)
		{
			name:       "Visa basic 16 digits",
			input:      "card is 4532015112830366",
			wantLen:    1,
			wantBrand:  detect.BrandVisa,
			wantRaw:    "4532015112830366",
			wantMinCon: 0.9,
		},
		{
			name: "Visa with dashes",

			input:      "4532-0151-1283-0366",
			wantLen:    1,
			wantBrand:  detect.BrandVisa,
			wantRaw:    "4532-0151-1283-0366",
			wantMinCon: 0.9,
		},
		{
			name: "Visa with spaces",

			input:      "4532 0151 1283 0366",
			wantLen:    1,
			wantBrand:  detect.BrandVisa,
			wantRaw:    "4532 0151 1283 0366",
			wantMinCon: 0.9,
		},
		{
			name:       "Mastercard 51-55 range",
			input:      "5425233430109903",
			wantLen:    1,
			wantBrand:  detect.BrandMastercard,
			wantRaw:    "5425233430109903",
			wantMinCon: 0.9,
		},
		{
			name:       "Amex 15 digits",
			input:      "374245455400126",
			wantLen:    1,
			wantBrand:  detect.BrandAmex,
			wantRaw:    "374245455400126",
			wantMinCon: 0.9,
		},
		{
			name:       "JCB 3528-3589",
			input:      "3566002020360505",
			wantLen:    1,
			wantBrand:  detect.BrandJCB,
			wantRaw:    "3566002020360505",
			wantMinCon: 0.9,
		},
		{
			name:       "Discover 6011 prefix",
			input:      "6011000400000000",
			wantLen:    1,
			wantBrand:  detect.BrandDiscover,
			wantRaw:    "6011000400000000",
			wantMinCon: 0.9,
		},
		{
			name:       "PAN in JSON value",
			input:      `{"card":"4532015112830366"}`,
			wantLen:    1,
			wantBrand:  detect.BrandVisa,
			wantRaw:    "4532015112830366",
			wantMinCon: 0.9,
		},
		{
			name:       "multiple PANs in one line",
			input:      "4532015112830366 and 5425233430109903",
			wantLen:    2,
			wantBrand:  "", // not checking brand for multi
			wantRaw:    "", // not checking raw for multi
			wantMinCon: 0.9,
		},

		// False positives that should NOT be detected
		{
			name:    "random 16 digits failing Luhn",
			input:   "1234567890123456",
			wantLen: 0,
		},
		{
			name:    "too short for PAN",
			input:   "4532015112",
			wantLen: 0,
		},
		{
			name:    "too long for PAN (20 digits)",
			input:   "45320151128303661234",
			wantLen: 0,
		},
		{

			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "no digits at all",
			input:   "hello world no numbers here",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantLen)
			}
			if tt.wantLen > 0 && tt.wantBrand != "" {
				f := findings[0]
				detail, ok := f.PANDetail()
				if !ok {
					t.Fatalf("PANDetail() returned false for PAN finding")
				}
				if detail.Brand != tt.wantBrand {
					t.Errorf("Brand = %q, want %q", detail.Brand, tt.wantBrand)
				}
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

func TestPANDetector_FullWidthRawValue(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	input := "４５３２０１５１１２８３０３６６"
	findings := d.Scan([]byte(input))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	// RawValue must match the original full-width text, not the normalized half-width.
	if f.RawValue != input {
		t.Errorf("RawValue = %q, want %q", f.RawValue, input)
	}
	// Start:End must slice back to the same string.
	if input[f.Start:f.End] != f.RawValue {
		t.Errorf("input[Start:End] = %q, RawValue = %q", input[f.Start:f.End], f.RawValue)
	}
}

func TestPANDetector_Name(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	if d.Name() != detect.NamePAN {
		t.Errorf("Name() = %q, want %q", d.Name(), detect.NamePAN)
	}
}

func TestPANDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice")
	}
}

func TestPANDetector_Brands(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	tests := []struct {
		name      string
		input     string
		wantBrand detect.CardBrand
	}{
		{name: "Mastercard 2-series low", input: "2221000000000009", wantBrand: detect.BrandMastercard},
		{name: "Mastercard 2-series high", input: "2720990000000007", wantBrand: detect.BrandMastercard},
		{name: "Discover 65 prefix", input: "6500000000000002", wantBrand: detect.BrandDiscover},
		{name: "Discover 644 prefix", input: "6440000000000007", wantBrand: detect.BrandDiscover},
		{name: "UnionPay 62 prefix", input: "6200000000000005", wantBrand: detect.BrandUnionPay},
		{name: "Diners 300 prefix", input: "30000000000004", wantBrand: detect.BrandDiners},
		{name: "Diners 36 prefix", input: "36000000000008", wantBrand: detect.BrandDiners},
		{name: "Diners 38 prefix", input: "38000000000006", wantBrand: detect.BrandDiners},
		{name: "Amex 34 prefix", input: "340000000000009", wantBrand: detect.BrandAmex},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) == 0 {
				t.Fatalf("got 0 findings, want >= 1")
			}
			detail, ok := findings[0].PANDetail()
			if !ok {
				t.Fatal("PANDetail() returned false")
			}
			if detail.Brand != tt.wantBrand {
				t.Errorf("Brand = %q, want %q", detail.Brand, tt.wantBrand)
			}
		})
	}
}

func TestPANDetector_UnknownBrandNotDetected(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	// Prefix '9' has no known brand, should not be reported.
	findings := d.Scan([]byte("9000000000000001"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for unknown brand, want 0", len(findings))
	}
}

func TestPANDetector_LuhnFailLowerConfidence(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	// Visa-prefixed 16 digits but Luhn fails — still detected with lower confidence.
	findings := d.Scan([]byte("4532015112830360"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Confidence >= 0.9 {
		t.Errorf("Confidence = %f, want < 0.9 for failed Luhn", findings[0].Confidence)
	}
}

func TestPANDetector_BrandLengthMismatchRejected(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Visa 19 digits with valid Luhn rejected",
			input: "4000056655665556106",
		},
		{
			name:  "Visa 14 digits with valid Luhn rejected",
			input: "40000566556652",
		},
		{
			name:  "Amex 16 digits with valid Luhn rejected",
			input: "3400000000000018",
		},
		{
			name:  "Mastercard 15 digits with valid Luhn rejected",
			input: "510000000000003",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0 (brand length mismatch should be rejected); findings=%+v",
					len(findings), findings)
			}
		})
	}
}

func TestPANDetector_Visa13Digits(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	findings := d.Scan([]byte("4222222222225"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].PANDetail()
	if !ok {
		t.Fatal("PANDetail() returned false")
	}
	if detail.Brand != detect.BrandVisa {
		t.Errorf("Brand = %q, want %q", detail.Brand, detect.BrandVisa)
	}
	if detail.Length != 13 {
		t.Errorf("Length = %d, want 13", detail.Length)
	}
}

func TestPANDetector_UnionPayLong(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	findings := d.Scan([]byte("6200000000000000003"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].PANDetail()
	if !ok {
		t.Fatal("PANDetail() returned false")
	}
	if detail.Brand != detect.BrandUnionPay {
		t.Errorf("Brand = %q, want %q", detail.Brand, detect.BrandUnionPay)
	}
}

func TestPANDetector_JCBOutOfRange(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	// 3527 is just below JCB range (3528-3589), prefix '35' with v=27.
	// This should not match as JCB. It might match as something else or not at all.
	findings := d.Scan([]byte("3527000000000000"))
	for _, f := range findings {
		detail, ok := f.PANDetail()
		if ok && detail.Brand == detect.BrandJCB {
			t.Error("3527 prefix should not match as JCB")
		}
	}
}

func TestPANDetector_Mastercard2SeriesOutOfRange(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	// 2220 is below Mastercard 2-series range (2221-2720).
	findings := d.Scan([]byte("2220000000000000"))
	for _, f := range findings {
		detail, ok := f.PANDetail()
		if ok && detail.Brand == detect.BrandMastercard {
			t.Error("2220 prefix should not match as Mastercard")
		}
	}
}

func TestPANDetector_UnknownBrand5Prefix(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	// Prefix '56' is not Mastercard (51-55), so identifyBrand returns "".
	findings := d.Scan([]byte("5600000000000008"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for prefix 56, want 0 (unknown brand)", len(findings))
	}
}

func TestPANDetector_UnknownBrand6Prefix(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	// Prefix '63' is not Discover/UnionPay, so identifyBrand returns "".
	findings := d.Scan([]byte("6300000000000006"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for prefix 63, want 0 (unknown brand)", len(findings))
	}
}

func TestPANDetector_UnknownBrand3Prefix(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	// Prefix '31' is not Amex/Diners/JCB, so identifyBrand returns "".
	findings := d.Scan([]byte("3100000000000005"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for prefix 31, want 0 (unknown brand)", len(findings))
	}
}

func TestPANDetector_TrailingSeparator(t *testing.T) {
	t.Parallel()

	d := detect.NewPAN()
	// PAN with trailing space should still detect correctly.
	findings := d.Scan([]byte("4532015112830366 "))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RawValue != "4532015112830366" {
		t.Errorf("RawValue = %q, want %q", findings[0].RawValue, "4532015112830366")
	}
}

func TestPANSpecificationVectors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/luhn.txt")
	if err != nil {
		t.Fatal(err)
	}
	for raw := range strings.FieldsSeq(string(data)) {
		got := detect.NewPAN().Scan([]byte(raw))
		if len(got) != 1 || got[0].RawValue != raw || got[0].Confidence < 0.99 {
			t.Fatalf("Luhn vector rejected: %s", raw)
		}
	}
}
