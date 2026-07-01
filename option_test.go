package sensitive

import (
	"strings"
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

func TestWithMinConfidence_clampsOutOfRangeValues(t *testing.T) {
	t.Parallel()

	t.Run("negative value is clamped to 0", func(t *testing.T) {
		t.Parallel()

		scanner := NewScanner(WithPAN(), WithMinConfidence(-0.5))
		findings := scanner.ScanString("4532015112830366")
		// minConfidence=0 means no filtering; PAN should still be found.
		if len(findings) == 0 {
			t.Fatal("expected PAN finding with clamped negative threshold")
		}
	})

	t.Run("value above 1 is clamped to 1", func(t *testing.T) {
		t.Parallel()

		scanner := NewScanner(WithPAN(), WithMinConfidence(1.2))
		findings := scanner.ScanString("4532015112830366")
		// minConfidence=1.0 filters findings with confidence < 1.0.
		// PAN confidence is ~1.0, so it should pass.
		for _, f := range findings {
			if f.Confidence < 1.0 {
				t.Errorf("finding %q has confidence %.2f, want >= 1.0", f.DetectorName, f.Confidence)
			}
		}
	})
}

func TestClampConfidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input float64
		want  float64
	}{
		{"negative is clamped to 0", -0.5, 0},
		{"zero stays 0", 0, 0},
		{"mid-range unchanged", 0.5, 0.5},
		{"one stays 1", 1.0, 1.0},
		{"above 1 is clamped to 1", 1.5, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := clampConfidence(tt.input)
			if got != tt.want {
				t.Errorf("clampConfidence(%f) = %f, want %f", tt.input, got, tt.want)
			}
		})
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
		{
			name:        "WithBTC",
			option:      WithBTC(),
			input:       "btc: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			expectName:  detector.NameBTC,
			expectMatch: true,
		},
		{
			name:        "WithETH",
			option:      WithETH(),
			input:       "eth: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
			expectName:  detector.NameETH,
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

func TestCredentialOptions_ScanEndToEnd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		option Option
		input  string
		want   detector.DetectorName
	}{
		{
			name:   "github fine-grained PAT",
			option: WithGitHubToken(),
			input:  "export GITHUB_TOKEN=github_pat_11ABCDE0000aaaaaAAAAAa_abcdefghij",
			want:   detector.NameGitHubToken,
		},
		{
			name:   "slack bot token",
			option: WithSlackToken(),
			input:  "SLACK_TOKEN=xoxb-1234567890-abcdefghijkl and more",
			want:   detector.NameSlackToken,
		},
		{
			name:   "google api key",
			option: WithGoogleAPIKey(),
			input:  "key: AIza" + strings.Repeat("A", 35),
			want:   detector.NameGoogleAPIKey,
		},
		{
			name:   "pem private key header",
			option: WithPrivateKeyPEM(),
			input:  "-----BEGIN EC PRIVATE" + " KEY-----\nbody",
			want:   detector.NamePrivateKeyPEM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			scanner := NewScanner(tt.option)
			findings := scanner.ScanString(tt.input)
			var found bool
			for _, f := range findings {
				if f.Is(tt.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("scanner did not detect %q in %q; findings=%+v", tt.want, tt.input, findings)
			}
		})
	}
}

func TestWithAll_IncludesCredentialDetectors(t *testing.T) {
	t.Parallel()

	scanner := NewScanner(WithAll())
	input := "github_pat_11ABCDE0000aaaaaAAAAAa_abcdefghij xoxb-1234567890-abcdefghijkl"
	findings := scanner.ScanString(input)
	var gh, slack bool
	for _, f := range findings {
		switch {
		case f.IsGitHubToken():
			gh = true
		case f.IsSlackToken():
			slack = true
		}
	}
	if !gh || !slack {
		t.Errorf("WithAll should detect github (%v) and slack (%v) tokens", gh, slack)
	}
}
