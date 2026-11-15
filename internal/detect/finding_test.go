package detect_test

import (
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

func TestFinding_Is(t *testing.T) {
	t.Parallel()

	f := detect.Finding{DetectorName: detect.NamePAN}

	if !f.Is(detect.NamePAN) {
		t.Error("Is(NamePAN) should return true for a PAN finding")
	}
	if f.Is(detect.NameEmail) {
		t.Error("Is(NameEmail) should return false for a PAN finding")
	}
}

func TestFinding_IsXXX(t *testing.T) {
	t.Parallel()

	tests := []struct {
		check    func(detect.Finding) bool
		name     string
		finding  detect.Finding
		wantTrue bool
	}{
		{name: "IsPAN true", finding: detect.Finding{DetectorName: detect.NamePAN}, check: detect.Finding.IsPAN, wantTrue: true},
		{name: "IsPAN false", finding: detect.Finding{DetectorName: detect.NameEmail}, check: detect.Finding.IsPAN, wantTrue: false},
		{name: "IsEmail true", finding: detect.Finding{DetectorName: detect.NameEmail}, check: detect.Finding.IsEmail, wantTrue: true},
		{name: "IsEmail false", finding: detect.Finding{DetectorName: detect.NamePAN}, check: detect.Finding.IsEmail, wantTrue: false},
		{name: "IsJPPhone true", finding: detect.Finding{DetectorName: detect.NameJPPhone}, check: detect.Finding.IsJPPhone, wantTrue: true},
		{name: "IsMyNumber true", finding: detect.Finding{DetectorName: detect.NameMyNumber}, check: detect.Finding.IsMyNumber, wantTrue: true},
		{name: "IsJWT true", finding: detect.Finding{DetectorName: detect.NameJWT}, check: detect.Finding.IsJWT, wantTrue: true},
		{name: "IsAWSKey true", finding: detect.Finding{DetectorName: detect.NameAWSKey}, check: detect.Finding.IsAWSKey, wantTrue: true},
		{name: "IsIBAN true", finding: detect.Finding{DetectorName: detect.NameIBAN}, check: detect.Finding.IsIBAN, wantTrue: true},
		{name: "IsIPAddr true", finding: detect.Finding{DetectorName: detect.NameIPAddr}, check: detect.Finding.IsIPAddr, wantTrue: true},
		{name: "IsSWIFTBIC true", finding: detect.Finding{DetectorName: detect.NameSWIFTBIC}, check: detect.Finding.IsSWIFTBIC, wantTrue: true},
		{name: "IsABARouting true", finding: detect.Finding{DetectorName: detect.NameABARouting}, check: detect.Finding.IsABARouting, wantTrue: true},
		{name: "IsUKSortCode true", finding: detect.Finding{DetectorName: detect.NameUKSortCode}, check: detect.Finding.IsUKSortCode, wantTrue: true},
		{name: "IsCVV true", finding: detect.Finding{DetectorName: detect.NameCVV}, check: detect.Finding.IsCVV, wantTrue: true},
		{name: "IsCardExpiry true", finding: detect.Finding{DetectorName: detect.NameCardExpiry}, check: detect.Finding.IsCardExpiry, wantTrue: true},
		{name: "IsPaymentToken true", finding: detect.Finding{DetectorName: detect.NamePaymentToken}, check: detect.Finding.IsPaymentToken, wantTrue: true},
		{name: "IsBankAccount true", finding: detect.Finding{DetectorName: detect.NameBankAccount}, check: detect.Finding.IsBankAccount, wantTrue: true},
		{name: "IsACHTrace true", finding: detect.Finding{DetectorName: detect.NameACHTrace}, check: detect.Finding.IsACHTrace, wantTrue: true},
		{name: "IsMerchantID true", finding: detect.Finding{DetectorName: detect.NameMerchantID}, check: detect.Finding.IsMerchantID, wantTrue: true},
		{name: "IsBTC true", finding: detect.Finding{DetectorName: detect.NameBTC}, check: detect.Finding.IsBTC, wantTrue: true},
		{name: "IsBTC false", finding: detect.Finding{DetectorName: detect.NameEmail}, check: detect.Finding.IsBTC, wantTrue: false},
		{name: "IsETH true", finding: detect.Finding{DetectorName: detect.NameETH}, check: detect.Finding.IsETH, wantTrue: true},
		{name: "IsETH false", finding: detect.Finding{DetectorName: detect.NameEmail}, check: detect.Finding.IsETH, wantTrue: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.check(tt.finding)
			if got != tt.wantTrue {
				t.Errorf("got %v, want %v", got, tt.wantTrue)
			}
		})
	}
}

func TestFinding_DetailAccessors_NewDetectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expect func(detect.Finding) bool
		name   string
		f      detect.Finding
	}{
		{
			name: "SWIFTBICDetail",
			f: detect.Finding{
				DetectorName: detect.NameSWIFTBIC,
				Detail:       &detect.SWIFTBICDetail{BankCode: "BOFA"},
			},
			expect: func(f detect.Finding) bool { _, ok := f.SWIFTBICDetail(); return ok },
		},
		{
			name: "ABARoutingDetail",
			f: detect.Finding{
				DetectorName: detect.NameABARouting,
				Detail:       &detect.ABARoutingDetail{FederalReserveDistrict: "02-New York"},
			},
			expect: func(f detect.Finding) bool { _, ok := f.ABARoutingDetail(); return ok },
		},
		{
			name: "UKSortCodeDetail",
			f: detect.Finding{
				DetectorName: detect.NameUKSortCode,
				//nolint:goconst // Each test states its fixture and expected result independently.
				Detail: &detect.UKSortCodeDetail{FormattedValue: "12-34-56"},
			},
			expect: func(f detect.Finding) bool { _, ok := f.UKSortCodeDetail(); return ok },
		},
		{
			name: "CVVDetail",
			f: detect.Finding{
				DetectorName: detect.NameCVV,
				Detail:       &detect.CVVDetail{DigitCount: 3},
			},
			expect: func(f detect.Finding) bool { _, ok := f.CVVDetail(); return ok },
		},
		{
			name: "CardExpiryDetail",
			f: detect.Finding{
				DetectorName: detect.NameCardExpiry,
				Detail:       &detect.CardExpiryDetail{Month: "12", Year: "25"},
			},
			expect: func(f detect.Finding) bool { _, ok := f.CardExpiryDetail(); return ok },
		},
		{
			name: "PaymentTokenDetail",
			f: detect.Finding{
				DetectorName: detect.NamePaymentToken,
				Detail:       &detect.PaymentTokenDetail{Provider: "Stripe"},
			},
			expect: func(f detect.Finding) bool { _, ok := f.PaymentTokenDetail(); return ok },
		},
		{
			name: "BankAccountDetail",
			f: detect.Finding{
				DetectorName: detect.NameBankAccount,
				Detail:       &detect.BankAccountDetail{Language: "en"},
			},
			expect: func(f detect.Finding) bool { _, ok := f.BankAccountDetail(); return ok },
		},
		{
			name: "ACHTraceDetail",
			f: detect.Finding{
				DetectorName: detect.NameACHTrace,
				Detail:       &detect.ACHTraceDetail{ODFIRoutingNumber: "02100002"},
			},
			expect: func(f detect.Finding) bool { _, ok := f.ACHTraceDetail(); return ok },
		},
		{
			name: "MerchantIDDetail",
			f: detect.Finding{
				DetectorName: detect.NameMerchantID,
				Detail:       &detect.MerchantIDDetail{IDType: "merchant"},
			},
			expect: func(f detect.Finding) bool { _, ok := f.MerchantIDDetail(); return ok },
		},
		{
			name: "BTCDetail",
			f: detect.Finding{
				DetectorName: detect.NameBTC,
				Detail:       &detect.BTCDetail{AddressType: detect.BTCAddressP2PKH},
			},
			expect: func(f detect.Finding) bool { _, ok := f.BTCDetail(); return ok },
		},
		{
			name: "ETHDetail",
			f: detect.Finding{
				DetectorName: detect.NameETH,
				Detail:       &detect.ETHDetail{EIP55: true},
			},
			expect: func(f detect.Finding) bool { _, ok := f.ETHDetail(); return ok },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !tt.expect(tt.f) {
				t.Errorf("%s() returned false", tt.name)
			}
		})
	}
}

func TestFinding_Level(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		wantStr    string
		confidence float64
		wantLevel  detect.ConfidenceLevel
	}{
		//nolint:goconst // Each test states its fixture and expected result independently.
		{name: "high confidence (1.0)", confidence: 1.0, wantLevel: detect.ConfidenceHigh, wantStr: "high"},
		{name: "high confidence (0.8)", confidence: 0.8, wantLevel: detect.ConfidenceHigh, wantStr: "high"},
		//nolint:goconst // Each test states its fixture and expected result independently.
		{name: "medium confidence (0.79)", confidence: 0.79, wantLevel: detect.ConfidenceMedium, wantStr: "medium"},
		{name: "medium confidence (0.4)", confidence: 0.4, wantLevel: detect.ConfidenceMedium, wantStr: "medium"},
		//nolint:goconst // Each test states its fixture and expected result independently.
		{name: "low confidence (0.39)", confidence: 0.39, wantLevel: detect.ConfidenceLow, wantStr: "low"},
		{name: "low confidence (0.0)", confidence: 0.0, wantLevel: detect.ConfidenceLow, wantStr: "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := detect.Finding{Confidence: tt.confidence}
			got := f.Level()
			if got != tt.wantLevel {
				t.Errorf("Level() = %v, want %v", got, tt.wantLevel)
			}
			if got.String() != tt.wantStr {
				t.Errorf("Level().String() = %q, want %q", got.String(), tt.wantStr)
			}
		})
	}
}

func TestConfidenceLevel_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		want  string
		level detect.ConfidenceLevel
	}{
		{level: detect.ConfidenceLow, want: "low"},
		{level: detect.ConfidenceMedium, want: "medium"},
		{level: detect.ConfidenceHigh, want: "high"},
		{level: detect.ConfidenceLevel(99), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := tt.level.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFinding_Kind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		detectorName detect.DetectorName
		wantKind     detect.SensitiveKind
	}{
		// Financial
		{name: "PAN is financial", detectorName: detect.NamePAN, wantKind: detect.KindFinancial},
		{name: "IBAN is financial", detectorName: detect.NameIBAN, wantKind: detect.KindFinancial},
		{name: "ABA routing is financial", detectorName: detect.NameABARouting, wantKind: detect.KindFinancial},
		{name: "UK sort code is financial", detectorName: detect.NameUKSortCode, wantKind: detect.KindFinancial},
		{name: "CVV is financial", detectorName: detect.NameCVV, wantKind: detect.KindFinancial},
		{name: "card expiry is financial", detectorName: detect.NameCardExpiry, wantKind: detect.KindFinancial},
		{name: "bank account is financial", detectorName: detect.NameBankAccount, wantKind: detect.KindFinancial},
		{name: "ACH trace is financial", detectorName: detect.NameACHTrace, wantKind: detect.KindFinancial},
		{name: "merchant ID is financial", detectorName: detect.NameMerchantID, wantKind: detect.KindFinancial},
		{name: "SWIFT/BIC is financial", detectorName: detect.NameSWIFTBIC, wantKind: detect.KindFinancial},
		{name: "BTC is financial", detectorName: detect.NameBTC, wantKind: detect.KindFinancial},
		{name: "ETH is financial", detectorName: detect.NameETH, wantKind: detect.KindFinancial},
		// PII
		{name: "email is PII", detectorName: detect.NameEmail, wantKind: detect.KindPII},
		{name: "JP phone is PII", detectorName: detect.NameJPPhone, wantKind: detect.KindPII},
		{name: "My Number is PII", detectorName: detect.NameMyNumber, wantKind: detect.KindPII},
		{name: "IP address is PII", detectorName: detect.NameIPAddr, wantKind: detect.KindPII},
		// Credential
		{name: "JWT is credential", detectorName: detect.NameJWT, wantKind: detect.KindCredential},
		{name: "AWS key is credential", detectorName: detect.NameAWSKey, wantKind: detect.KindCredential},
		{name: "payment token is credential", detectorName: detect.NamePaymentToken, wantKind: detect.KindCredential},
		// Unknown
		{name: "custom detector returns empty", detectorName: detect.DetectorName("custom"), wantKind: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := detect.Finding{DetectorName: tt.detectorName}
			if got := f.Kind(); got != tt.wantKind {
				t.Errorf("Kind() = %q, want %q", got, tt.wantKind)
			}
		})
	}
}
