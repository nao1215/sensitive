package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestPaymentTokenDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewPaymentToken()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
		wantMinCon float64
	}{
		{
			name:       "Stripe secret key live",
			input:      "key: sk_live_4eC39HqLyjWDarjtT1zdp7dc",
			wantLen:    1,
			wantRaw:    "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe publishable key live",
			input:      "key: pk_live_4eC39HqLyjWDarjtT1zdp7dc",
			wantLen:    1,
			wantRaw:    "pk_live_4eC39HqLyjWDarjtT1zdp7dc",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe secret key test",
			input:      "key: sk_test_4eC39HqLyjWDarjtT1zdp7dc",
			wantLen:    1,
			wantRaw:    "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe token",
			input:      "tok_1MiN3dLkdIwHu7ixt12345AB",
			wantLen:    1,
			wantRaw:    "tok_1MiN3dLkdIwHu7ixt12345AB",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe payment intent",
			input:      "pi_3MtwBwLkdIwHu7ix28a3tqPa",
			wantLen:    1,
			wantRaw:    "pi_3MtwBwLkdIwHu7ix28a3tqPa",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe payment method",
			input:      "pm_1MiN3dLkdIwHu7ixt12345AB",
			wantLen:    1,
			wantRaw:    "pm_1MiN3dLkdIwHu7ixt12345AB",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe customer",
			input:      "cus_4eC39HqLyjWDarjtT1zdp7dc",
			wantLen:    1,
			wantRaw:    "cus_4eC39HqLyjWDarjtT1zdp7dc",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe subscription",
			input:      "sub_4eC39HqLyjWDarjtT1zdp7dc",
			wantLen:    1,
			wantRaw:    "sub_4eC39HqLyjWDarjtT1zdp7dc",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe price",
			input:      "price_4eC39HqLyjWDarjt",
			wantLen:    1,
			wantRaw:    "price_4eC39HqLyjWDarjt",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe product",
			input:      "prod_4eC39HqLyjWDarjt",
			wantLen:    1,
			wantRaw:    "prod_4eC39HqLyjWDarjt",
			wantMinCon: 0.85,
		},
		{
			name:       "PayPal payment ID",
			input:      "PAYID-ABCDEFGHIJKLMNOP1234",
			wantLen:    1,
			wantRaw:    "PAYID-ABCDEFGHIJKLMNOP1234",
			wantMinCon: 0.85,
		},
		{
			name:       "Square application ID",
			input:      "sq0idp-ABCDEFGHIJKLMNOP1234",
			wantLen:    1,
			wantRaw:    "sq0idp-ABCDEFGHIJKLMNOP1234",
			wantMinCon: 0.85,
		},
		{
			name:       "Square application secret",
			input:      "sq0csp-ABCDEFGHIJKLMNOP1234",
			wantLen:    1,
			wantRaw:    "sq0csp-ABCDEFGHIJKLMNOP1234",
			wantMinCon: 0.85,
		},
		{
			name:       "Stripe token body too short",
			input:      "tok_abc",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "preceded by alphanumeric",
			input:      "Xsk_live_4eC39HqLyjWDarjtT1zdp7dc",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "preceded by underscore",
			input:      "_sk_live_4eC39HqLyjWDarjtT1zdp7dc",
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
			name:       "no token prefix",
			input:      "just some random text with numbers 12345",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
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

func TestPaymentTokenDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewPaymentToken()
	findings := d.Scan([]byte("sk_live_4eC39HqLyjWDarjtT1zdp7dc"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	detail, ok := findings[0].PaymentTokenDetail()
	if !ok {
		t.Fatal("PaymentTokenDetail() returned false")
	}
	if detail.Provider != "Stripe" {
		t.Errorf("Provider = %q, want %q", detail.Provider, "Stripe")
	}
	if detail.TokenType != "secret_key" {
		t.Errorf("TokenType = %q, want %q", detail.TokenType, "secret_key")
	}
}

func TestPaymentTokenDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewPaymentToken()
	if d.Name() != detector.NamePaymentToken {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NamePaymentToken)
	}
}

func TestPaymentTokenDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewPaymentToken()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}
