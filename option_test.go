package sensitive

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestWithDetector_nilDetectorIsIgnored(t *testing.T) {
	t.Parallel()

	// WithDetector(nil) should not cause a panic and the nil detector
	// should be silently discarded.
	scanner := NewScanner(WithDetector(nil), WithPAN())
	findings := scanner.ScanString("4532015112830366")
	if len(findings) != 1 {
		t.Fatalf("want 1 PAN finding, got %d", len(findings))
	}
}

func TestNewScanner_nilOptionIsIgnored(t *testing.T) {
	t.Parallel()

	// A nil Option in the variadic list should not cause a panic.
	scanner := NewScanner(nil, WithPAN())
	findings := scanner.ScanString("4532015112830366")
	if len(findings) != 1 {
		t.Fatalf("want 1 PAN finding, got %d", len(findings))
	}
}

func TestOptions_NewDetectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		option      Option
		input       string
		expectName  detector.DetectorName
		expectMatch bool
	}{
		{
			name:        "WithSWIFTBIC",
			option:      WithSWIFTBIC(),
			input:       "SWIFT: DEUTDEFF",
			expectName:  detector.NameSWIFTBIC,
			expectMatch: true,
		},
		{
			name:        "WithABARouting",
			option:      WithABARouting(),
			input:       "routing: 021000021",
			expectName:  detector.NameABARouting,
			expectMatch: true,
		},
		{
			name:        "WithUKSortCode",
			option:      WithUKSortCode(),
			input:       "sort code: 12-34-56",
			expectName:  detector.NameUKSortCode,
			expectMatch: true,
		},
		{
			name:        "WithCVV",
			option:      WithCVV(),
			input:       "CVV 123",
			expectName:  detector.NameCVV,
			expectMatch: true,
		},
		{
			name:        "WithCardExpiry",
			option:      WithCardExpiry(),
			input:       "exp 12/29",
			expectName:  detector.NameCardExpiry,
			expectMatch: true,
		},
		{
			name:        "WithPaymentToken",
			option:      WithPaymentToken(),
			input:       "sk_live_1234567890abcdef",
			expectName:  detector.NamePaymentToken,
			expectMatch: true,
		},
		{
			name:        "WithBankAccount",
			option:      WithBankAccount(),
			input:       "bank account 12345678",
			expectName:  detector.NameBankAccount,
			expectMatch: true,
		},
		{
			name:        "WithACHTrace",
			option:      WithACHTrace(),
			input:       "ACH trace 021000021123456",
			expectName:  detector.NameACHTrace,
			expectMatch: true,
		},
		{
			name:        "WithMerchantID",
			option:      WithMerchantID(),
			input:       "merchant ID ABCDE12345FGHI6",
			expectName:  detector.NameMerchantID,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := NewScanner(tt.option)
			findings := scanner.ScanString(tt.input)
			if tt.expectMatch && len(findings) == 0 {
				t.Fatalf("expected at least 1 finding, got 0")
			}
			if !tt.expectMatch && len(findings) > 0 {
				t.Fatalf("expected 0 findings, got %d", len(findings))
			}
			if len(findings) > 0 && findings[0].DetectorName != tt.expectName {
				t.Errorf("DetectorName = %q, want %q", findings[0].DetectorName, tt.expectName)
			}
		})
	}
}
