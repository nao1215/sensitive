package detect

import (
	"os"
	"strings"
	"testing"
)

func TestPANDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	tests := []struct {
		name       string
		input      string
		wantBrand  CardBrand
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		// Valid PANs (well-known test numbers)
		{
			name:       "Visa basic 16 digits",
			input:      "card is 4532015112830366",
			wantLen:    1,
			wantBrand:  BrandVisa,
			wantRaw:    "4532015112830366",
			wantMinCon: 0.9,
		},
		{
			name:       "Visa with dashes",
			input:      "4532-0151-1283-0366",
			wantLen:    1,
			wantBrand:  BrandVisa,
			wantRaw:    "4532-0151-1283-0366",
			wantMinCon: 0.9,
		},
		{
			name:       "Visa with spaces",
			input:      "4532 0151 1283 0366",
			wantLen:    1,
			wantBrand:  BrandVisa,
			wantRaw:    "4532 0151 1283 0366",
			wantMinCon: 0.9,
		},
		{
			name:       "Mastercard 51-55 range",
			input:      "5425233430109903",
			wantLen:    1,
			wantBrand:  BrandMastercard,
			wantRaw:    "5425233430109903",
			wantMinCon: 0.9,
		},
		{
			name:       "Amex 15 digits",
			input:      "374245455400126",
			wantLen:    1,
			wantBrand:  BrandAmex,
			wantRaw:    "374245455400126",
			wantMinCon: 0.9,
		},
		{
			name:       "JCB 3528-3589",
			input:      "3566002020360505",
			wantLen:    1,
			wantBrand:  BrandJCB,
			wantRaw:    "3566002020360505",
			wantMinCon: 0.9,
		},
		{
			name:       "Discover 6011 prefix",
			input:      "6011000400000000",
			wantLen:    1,
			wantBrand:  BrandDiscover,
			wantRaw:    "6011000400000000",
			wantMinCon: 0.9,
		},
		{
			name:       "PAN in JSON value",
			input:      `{"card":"4532015112830366"}`,
			wantLen:    1,
			wantBrand:  BrandVisa,
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
			name:    emptyInputCase,
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
				digits := testDigits([]byte(tt.input[f.Start:f.End]))
				if identifyBrand(digits) != tt.wantBrand {
					t.Errorf("Brand = %q, want %q", identifyBrand(digits), tt.wantBrand)
				}
			}
			if tt.wantLen > 0 && tt.wantRaw != "" {
				if tt.input[findings[0].Start:findings[0].End] != tt.wantRaw {
					t.Errorf("matched text = %q, want %q", tt.input[findings[0].Start:findings[0].End], tt.wantRaw)
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

func TestPANDetector_FullWidthSpan(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	input := "４５３２０１５１１２８３０３６６"
	findings := d.Scan([]byte(input))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	// matched text must match the original full-width text, not the normalized half-width.
	if input[f.Start:f.End] != input {
		t.Errorf("matched text = %q, want %q", input[f.Start:f.End], input)
	}
	// Start:End must slice back to the same string.
}

func TestPANDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	if d.Name() != NamePAN {
		t.Errorf("Name() = %q, want %q", d.Name(), NamePAN)
	}
}

func TestPANDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice")
	}
}

func TestPANDetector_Brands(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	tests := []struct {
		name      string
		input     string
		wantBrand CardBrand
	}{
		{name: "Mastercard 2-series low", input: "2221000000000009", wantBrand: BrandMastercard},
		{name: "Mastercard 2-series high", input: "2720990000000007", wantBrand: BrandMastercard},
		{name: "Discover 65 prefix", input: "6500000000000002", wantBrand: BrandDiscover},
		{name: "Discover 644 prefix", input: "6440000000000005", wantBrand: BrandDiscover},
		{name: "UnionPay 62 prefix", input: "6200000000000005", wantBrand: BrandUnionPay},
		{name: "Diners 300 prefix", input: "30000000000004", wantBrand: BrandDiners},
		{name: "Diners 36 prefix", input: "36000000000008", wantBrand: BrandDiners},
		{name: "Diners 38 prefix", input: "38000000000006", wantBrand: BrandDiners},
		{name: "Amex 34 prefix", input: "340000000000009", wantBrand: BrandAmex},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) == 0 {
				t.Fatalf("got 0 findings, want >= 1")
			}
			digits := testDigits([]byte(tt.input[findings[0].Start:findings[0].End]))
			if identifyBrand(digits) != tt.wantBrand {
				t.Errorf("Brand = %q, want %q", identifyBrand(digits), tt.wantBrand)
			}
		})
	}
}

func TestPANDetector_UnknownBrandNotDetected(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	// Prefix '9' has no known brand, should not be reported.
	findings := d.Scan([]byte("9000000000000001"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for unknown brand, want 0", len(findings))
	}
}

func TestPANDetector_LuhnFailLowerConfidence(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	// Every issued card number satisfies Luhn, so Visa-prefixed digits that
	// fail it are an order, request or trace ID, not a card.
	for _, text := range []string{"4532015112830360", "order_id=4532015112830360", "dd.span_id=5206839345487757220"} {
		if findings := d.Scan([]byte(text)); len(findings) != 0 {
			t.Errorf("%s: got %v, want no finding for a failed Luhn check", text, findings)
		}
	}
	if findings := d.Scan([]byte("4532015112830366")); len(findings) != 1 || findings[0].Confidence != 1.0 {
		t.Fatalf("Luhn-valid Visa: got %v, want one finding at 1.0", findings)
	}
}

func TestPANDetector_BrandLengthMismatchRejected(t *testing.T) {
	t.Parallel()

	d := NewPAN()
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

	d := NewPAN()
	findings := d.Scan([]byte("4222222222222"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	digits := testDigits([]byte("4222222222222"[findings[0].Start:findings[0].End]))
	if identifyBrand(digits) != BrandVisa {
		t.Errorf("Brand = %q, want %q", identifyBrand(digits), BrandVisa)
	}
	if len(digits) != 13 {
		t.Errorf("Length = %d, want 13", len(digits))
	}
}

func TestPANDetector_UnionPayLong(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	findings := d.Scan([]byte("6200000000000000000"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	digits := testDigits([]byte("6200000000000000000"[findings[0].Start:findings[0].End]))
	if identifyBrand(digits) != BrandUnionPay {
		t.Errorf("Brand = %q, want %q", identifyBrand(digits), BrandUnionPay)
	}
}

func TestPANDetector_JCBOutOfRange(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	// 3527 is just below JCB range (3528-3589), prefix '35' with v=27.
	// This should not match as JCB. It might match as something else or not at all.
	findings := d.Scan([]byte("3527000000000000"))
	for _, f := range findings {
		digits := testDigits([]byte("3527000000000000"[f.Start:f.End]))
		if identifyBrand(digits) == BrandJCB {
			t.Error("3527 prefix should not match as JCB")
		}
	}
}

func TestPANDetector_Mastercard2SeriesOutOfRange(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	// 2220 is below Mastercard 2-series range (2221-2720).
	findings := d.Scan([]byte("2220000000000000"))
	for _, f := range findings {
		digits := testDigits([]byte("2220000000000000"[f.Start:f.End]))
		if identifyBrand(digits) == BrandMastercard {
			t.Error("2220 prefix should not match as Mastercard")
		}
	}
}

func TestPANDetector_UnknownBrand5Prefix(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	// Prefix '56' is not Mastercard (51-55), so identifyBrand returns "".
	findings := d.Scan([]byte("5600000000000008"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for prefix 56, want 0 (unknown brand)", len(findings))
	}
}

func TestPANDetector_UnknownBrand6Prefix(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	// Prefix '63' is not Discover/UnionPay, so identifyBrand returns "".
	findings := d.Scan([]byte("6300000000000006"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for prefix 63, want 0 (unknown brand)", len(findings))
	}
}

func TestPANDetector_UnknownBrand3Prefix(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	// Prefix '31' is not Amex/Diners/JCB, so identifyBrand returns "".
	findings := d.Scan([]byte("3100000000000005"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for prefix 31, want 0 (unknown brand)", len(findings))
	}
}

func TestPANDetector_TrailingSeparator(t *testing.T) {
	t.Parallel()

	d := NewPAN()
	// PAN with trailing space should still detect correctly.
	findings := d.Scan([]byte("4532015112830366 "))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if "4532015112830366 "[findings[0].Start:findings[0].End] != "4532015112830366" {
		t.Errorf("matched text = %q, want %q", "4532015112830366 "[findings[0].Start:findings[0].End], "4532015112830366")
	}
}

func TestPANSpecificationVectors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/luhn.txt")
	if err != nil {
		t.Fatal(err)
	}
	for raw := range strings.FieldsSeq(string(data)) {
		got := NewPAN().Scan([]byte(raw))
		if len(got) != 1 || raw[got[0].Start:got[0].End] != raw || got[0].Confidence < 0.99 {
			t.Fatalf("Luhn vector rejected: %s", raw)
		}
	}
}

func TestPANRejectsIdentifierFragments(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"d55593266701308e", "a4532015112830366", "4532015112830366f", "_4532015112830366", "4532015112830366_", "a４５３２０１５１１２８３０３６６f"} {
		if got := NewPAN().Scan([]byte(text)); len(got) != 0 {
			t.Errorf("identifier fragment reported as PAN: %q", text)
		}
	}
	for _, text := range []string{"4532015112830366", "card=4532-0151-1283-0366", "v%3D4532015112830366", "カード４５３２０１５１１２８３０３６６"} {
		if got := NewPAN().Scan([]byte(text)); len(got) != 1 {
			t.Errorf("delimited PAN missing: %q", text)
		}
	}
}

func TestPANPrefixAndLengthEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		prefix string
		brand  CardBrand
	}{
		{"51", BrandMastercard},
		{"55", BrandMastercard},
		{"50", ""},
		{"56", ""},
		{"3527", ""},
		{"3528", BrandJCB},
		{"3589", BrandJCB},
		{"3590", ""},
		{"643", ""},
		{"644", BrandDiscover},
		{"649", BrandDiscover},
		{"650", BrandDiscover},
	} {
		raw := luhnComplete(tc.prefix + strings.Repeat("0", 15-len(tc.prefix)))
		got := NewPAN().Scan([]byte(raw))
		if tc.brand == "" {
			if len(got) != 0 {
				t.Fatal(tc.prefix, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Fatal(tc.prefix, got)
		}
		digits := testDigits([]byte(raw[got[0].Start:got[0].End]))
		if identifyBrand(digits) != tc.brand {
			t.Fatal(tc.prefix, got)
		}
	}
	for _, n := range []int{15, 16, 19, 20} {
		if isExpectedLength(BrandUnionPay, n) != (n == 16 || n == 19) {
			t.Fatal("UnionPay length", n)
		}
	}
}

func TestPanRejectedBoundaries(t *testing.T) {
	t.Parallel()
	if identifyBrand(nil) != "" || isExpectedLength("unknown", 16) {
		t.Fatal("unknown brand accepted")
	}
}

func TestPANChecksumSingleDigitChanges(t *testing.T) {
	t.Parallel()
	digits := []byte(samplePAN)
	for i, original := range digits {
		for replacement := byte('0'); replacement <= '9'; replacement++ {
			digits[i] = replacement
			if passesLuhn(digits) != (replacement == original) {
				t.Fatal(i, replacement)
			}
		}
		digits[i] = original
	}
}

// luhnComplete appends the check digit that makes body pass Luhn.
func luhnComplete(body string) string {
	for check := '0'; check <= '9'; check++ {
		if candidate := body + string(check); passesLuhn([]byte(candidate)) {
			return candidate
		}
	}
	panic("no Luhn check digit")
}

func TestPANSkipsJANProductCodes(t *testing.T) {
	t.Parallel()
	// 4901234567894 passes both Luhn and the EAN-13 check digit.
	for _, input := range []string{"JAN 4901234567894", "barcode=4901234567894", `{"jan":"4901234567894"}`} {
		if got := NewPAN().Scan([]byte(input)); len(got) != 0 {
			t.Errorf("Scan(%q) = %+v, want none", input, got)
		}
	}
	// 4222222222222 is a published 13-digit Visa test number that fails EAN-13.
	if got := NewPAN().Scan([]byte("card 4222222222222")); len(got) != 1 {
		t.Fatalf("13-digit Visa lost: %+v", got)
	}
	if !passesEAN13([]byte("4901234567894")) || passesEAN13([]byte("4222222222222")) {
		t.Fatal("EAN-13 check digit")
	}
}

func TestPANDottedGroups(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input string
		found bool
	}{
		{"card 4111.1111.1111.1111", true},
		{"card 4111.1111.1111.1111.", true},
		{"card 4111.1111.1111.1111.5", false},
		{"oid 4111.1111.1111.11111", false},
		{"v 4111.1111.111.11111", false},
		{"card 4111.1111.1111.1112", false},
	} {
		if got := NewPAN().Scan([]byte(tc.input)); (len(got) == 1) != tc.found {
			t.Errorf("Scan(%q) = %+v, want found %v", tc.input, got, tc.found)
		}
	}
}

func TestPANDottedGroupEnds(t *testing.T) {
	t.Parallel()
	for input, found := range map[string]bool{
		"4111.1111.1111.1111. ok": true,
		"4111.1111.1111.111":      false,
		"4111.1111.1111.1111.":    true,
	} {
		if got := NewPAN().Scan([]byte(input)); (len(got) == 1) != found {
			t.Errorf("Scan(%q) = %+v, want found %v", input, got, found)
		}
	}
	// Weights 1 and 3 alternate from the left; swapping them breaks these codes.
	for _, code := range []string{"4512345678906", "4900000000108", "4522222222221"} {
		if !passesEAN13([]byte(code)) {
			t.Errorf("EAN-13 %s rejected", code)
		}
	}
}
