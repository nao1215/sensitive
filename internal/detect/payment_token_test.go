package detect

import (
	"testing"
)

func TestPaymentTokenDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewPaymentToken()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
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
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		{
			name:       "preceded by alphanumeric",
			input:      "Xsk_live_4eC39HqLyjWDarjtT1zdp7dc",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		{
			name:       "preceded by underscore",
			input:      "_sk_live_4eC39HqLyjWDarjtT1zdp7dc",
			wantLen:    0,
			wantRaw:    "",
			wantMinCon: 0,
		},
		{
			name:       "empty payment token input",
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
			if tt.wantRaw != "" && tt.input[findings[0].Start:findings[0].End] != tt.wantRaw {
				t.Errorf("matched text = %q, want %q", tt.input[findings[0].Start:findings[0].End], tt.wantRaw)
			}
			for _, f := range findings {
				if f.Confidence < tt.wantMinCon {
					t.Errorf("Confidence = %f, want >= %f", f.Confidence, tt.wantMinCon)
				}
			}
		})
	}
}

func TestPaymentTokenDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewPaymentToken()
	findings := d.Scan([]byte("sk_live_4eC39HqLyjWDarjtT1zdp7dc"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Start != 0 || findings[0].End != len("sk_live_4eC39HqLyjWDarjtT1zdp7dc") || findings[0].Confidence != 0.9 {
		t.Fatal(findings)
	}
}

func TestPaymentTokenDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewPaymentToken()
	if d.Name() != NamePaymentToken {
		t.Errorf("Name() = %q, want %q", d.Name(), NamePaymentToken)
	}
}

func TestPaymentTokenDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewPaymentToken()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}
