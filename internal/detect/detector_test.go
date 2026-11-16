package detect

import (
	"testing"
)

const (
	samplePAN      = "4242424242424242"
	sampleMyNumber = "123456789018"
	sampleMobile   = "090-1234-5678"
	sampleLandline = "03-1234-5678"
	sampleSortCode = "12-34-56"
	sampleBase58   = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	sampleBech32   = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	// #nosec G101 -- AWS publishes this example access key; it is not an authentication credential.
	sampleAccessKey  = "AKIAIOSFODNN7EXAMPLE"
	sampleIBAN       = "GB82WEST12345698765432"
	loopbackIPv4     = "127.0.0.1"
	loopbackIPv6     = "::1"
	emptyInputCase   = "empty input"
	sampleMerchantID = "ABCDE12345FGHI6"
	noKeywordCase    = "no keyword"
)

func TestFinding_Is(t *testing.T) {
	t.Parallel()

	f := Finding{DetectorName: NamePAN}

	if !f.Is(NamePAN) {
		t.Error("Is(NamePAN) should return true for a PAN finding")
	}
	if f.Is(NameEmail) {
		t.Error("Is(NameEmail) should return false for a PAN finding")
	}
}

func TestFinding_IsXXX(t *testing.T) {
	t.Parallel()

	tests := []struct {
		check    func(Finding) bool
		name     string
		finding  Finding
		wantTrue bool
	}{
		{name: "IsPAN true", finding: Finding{DetectorName: NamePAN}, check: Finding.IsPAN, wantTrue: true},
		{name: "IsPAN false", finding: Finding{DetectorName: NameEmail}, check: Finding.IsPAN, wantTrue: false},
		{name: "IsEmail true", finding: Finding{DetectorName: NameEmail}, check: Finding.IsEmail, wantTrue: true},
		{name: "IsEmail false", finding: Finding{DetectorName: NamePAN}, check: Finding.IsEmail, wantTrue: false},
		{name: "IsJPPhone true", finding: Finding{DetectorName: NameJPPhone}, check: Finding.IsJPPhone, wantTrue: true},
		{name: "IsMyNumber true", finding: Finding{DetectorName: NameMyNumber}, check: Finding.IsMyNumber, wantTrue: true},
		{name: "IsJWT true", finding: Finding{DetectorName: NameJWT}, check: Finding.IsJWT, wantTrue: true},
		{name: "IsAWSKey true", finding: Finding{DetectorName: NameAWSKey}, check: Finding.IsAWSKey, wantTrue: true},
		{name: "IsIBAN true", finding: Finding{DetectorName: NameIBAN}, check: Finding.IsIBAN, wantTrue: true},
		{name: "IsIPAddr true", finding: Finding{DetectorName: NameIPAddr}, check: Finding.IsIPAddr, wantTrue: true},
		{name: "IsSWIFTBIC true", finding: Finding{DetectorName: NameSWIFTBIC}, check: Finding.IsSWIFTBIC, wantTrue: true},
		{name: "IsABARouting true", finding: Finding{DetectorName: NameABARouting}, check: Finding.IsABARouting, wantTrue: true},
		{name: "IsUKSortCode true", finding: Finding{DetectorName: NameUKSortCode}, check: Finding.IsUKSortCode, wantTrue: true},
		{name: "IsCVV true", finding: Finding{DetectorName: NameCVV}, check: Finding.IsCVV, wantTrue: true},
		{name: "IsCardExpiry true", finding: Finding{DetectorName: NameCardExpiry}, check: Finding.IsCardExpiry, wantTrue: true},
		{name: "IsPaymentToken true", finding: Finding{DetectorName: NamePaymentToken}, check: Finding.IsPaymentToken, wantTrue: true},
		{name: "IsBankAccount true", finding: Finding{DetectorName: NameBankAccount}, check: Finding.IsBankAccount, wantTrue: true},
		{name: "IsACHTrace true", finding: Finding{DetectorName: NameACHTrace}, check: Finding.IsACHTrace, wantTrue: true},
		{name: "IsMerchantID true", finding: Finding{DetectorName: NameMerchantID}, check: Finding.IsMerchantID, wantTrue: true},
		{name: "IsBTC true", finding: Finding{DetectorName: NameBTC}, check: Finding.IsBTC, wantTrue: true},
		{name: "IsBTC false", finding: Finding{DetectorName: NameEmail}, check: Finding.IsBTC, wantTrue: false},
		{name: "IsETH true", finding: Finding{DetectorName: NameETH}, check: Finding.IsETH, wantTrue: true},
		{name: "IsETH false", finding: Finding{DetectorName: NameEmail}, check: Finding.IsETH, wantTrue: false},
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
		expect func(Finding) bool
		name   string
		f      Finding
	}{
		{
			name: "SWIFTBICDetail",
			f: Finding{
				DetectorName: NameSWIFTBIC,
				Detail:       &SWIFTBICDetail{BankCode: "BOFA"},
			},
			expect: func(f Finding) bool { _, ok := f.SWIFTBICDetail(); return ok },
		},
		{
			name: "ABARoutingDetail",
			f: Finding{
				DetectorName: NameABARouting,
				Detail:       &ABARoutingDetail{FederalReserveDistrict: "02-New York"},
			},
			expect: func(f Finding) bool { _, ok := f.ABARoutingDetail(); return ok },
		},
		{
			name: "UKSortCodeDetail",
			f: Finding{
				DetectorName: NameUKSortCode,
				Detail:       &UKSortCodeDetail{FormattedValue: sampleSortCode},
			},
			expect: func(f Finding) bool { _, ok := f.UKSortCodeDetail(); return ok },
		},
		{
			name: "CVVDetail",
			f: Finding{
				DetectorName: NameCVV,
				Detail:       &CVVDetail{DigitCount: 3},
			},
			expect: func(f Finding) bool { _, ok := f.CVVDetail(); return ok },
		},
		{
			name: "CardExpiryDetail",
			f: Finding{
				DetectorName: NameCardExpiry,
				Detail:       &CardExpiryDetail{Month: "12", Year: "25"},
			},
			expect: func(f Finding) bool { _, ok := f.CardExpiryDetail(); return ok },
		},
		{
			name: "PaymentTokenDetail",
			f: Finding{
				DetectorName: NamePaymentToken,
				Detail:       &PaymentTokenDetail{Provider: "Stripe"},
			},
			expect: func(f Finding) bool { _, ok := f.PaymentTokenDetail(); return ok },
		},
		{
			name: "BankAccountDetail",
			f: Finding{
				DetectorName: NameBankAccount,
				Detail:       &BankAccountDetail{Language: "en"},
			},
			expect: func(f Finding) bool { _, ok := f.BankAccountDetail(); return ok },
		},
		{
			name: "ACHTraceDetail",
			f: Finding{
				DetectorName: NameACHTrace,
				Detail:       &ACHTraceDetail{ODFIRoutingNumber: "02100002"},
			},
			expect: func(f Finding) bool { _, ok := f.ACHTraceDetail(); return ok },
		},
		{
			name: "MerchantIDDetail",
			f: Finding{
				DetectorName: NameMerchantID,
				Detail:       &MerchantIDDetail{IDType: "merchant"},
			},
			expect: func(f Finding) bool { _, ok := f.MerchantIDDetail(); return ok },
		},
		{
			name: "BTCDetail",
			f: Finding{
				DetectorName: NameBTC,
				Detail:       &BTCDetail{AddressType: BTCAddressP2PKH},
			},
			expect: func(f Finding) bool { _, ok := f.BTCDetail(); return ok },
		},
		{
			name: "ETHDetail",
			f: Finding{
				DetectorName: NameETH,
				Detail:       &ETHDetail{EIP55: true},
			},
			expect: func(f Finding) bool { _, ok := f.ETHDetail(); return ok },
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
		wantLevel  ConfidenceLevel
	}{
		//nolint:goconst // Each test states its fixture and expected result independently.
		{name: "high confidence (1.0)", confidence: 1.0, wantLevel: ConfidenceHigh, wantStr: "high"},
		{name: "high confidence (0.8)", confidence: 0.8, wantLevel: ConfidenceHigh, wantStr: "high"},
		//nolint:goconst // Each test states its fixture and expected result independently.
		{name: "medium confidence (0.79)", confidence: 0.79, wantLevel: ConfidenceMedium, wantStr: "medium"},
		{name: "medium confidence (0.4)", confidence: 0.4, wantLevel: ConfidenceMedium, wantStr: "medium"},
		//nolint:goconst // Each test states its fixture and expected result independently.
		{name: "low confidence (0.39)", confidence: 0.39, wantLevel: ConfidenceLow, wantStr: "low"},
		{name: "low confidence (0.0)", confidence: 0.0, wantLevel: ConfidenceLow, wantStr: "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := Finding{Confidence: tt.confidence}
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
		level ConfidenceLevel
	}{
		{level: ConfidenceLow, want: "low"},
		{level: ConfidenceMedium, want: "medium"},
		{level: ConfidenceHigh, want: "high"},
		{level: ConfidenceLevel(99), want: "unknown"},
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
		detectorName DetectorName
		wantKind     SensitiveKind
	}{
		// Financial
		{name: "PAN is financial", detectorName: NamePAN, wantKind: KindFinancial},
		{name: "IBAN is financial", detectorName: NameIBAN, wantKind: KindFinancial},
		{name: "ABA routing is financial", detectorName: NameABARouting, wantKind: KindFinancial},
		{name: "UK sort code is financial", detectorName: NameUKSortCode, wantKind: KindFinancial},
		{name: "CVV is financial", detectorName: NameCVV, wantKind: KindFinancial},
		{name: "card expiry is financial", detectorName: NameCardExpiry, wantKind: KindFinancial},
		{name: "bank account is financial", detectorName: NameBankAccount, wantKind: KindFinancial},
		{name: "ACH trace is financial", detectorName: NameACHTrace, wantKind: KindFinancial},
		{name: "merchant ID is financial", detectorName: NameMerchantID, wantKind: KindFinancial},
		{name: "SWIFT/BIC is financial", detectorName: NameSWIFTBIC, wantKind: KindFinancial},
		{name: "BTC is financial", detectorName: NameBTC, wantKind: KindFinancial},
		{name: "ETH is financial", detectorName: NameETH, wantKind: KindFinancial},
		// PII
		{name: "email is PII", detectorName: NameEmail, wantKind: KindPII},
		{name: "JP phone is PII", detectorName: NameJPPhone, wantKind: KindPII},
		{name: "My Number is PII", detectorName: NameMyNumber, wantKind: KindPII},
		{name: "IP address is PII", detectorName: NameIPAddr, wantKind: KindPII},
		// Credential
		{name: "JWT is credential", detectorName: NameJWT, wantKind: KindCredential},
		{name: "AWS key is credential", detectorName: NameAWSKey, wantKind: KindCredential},
		{name: "payment token is credential", detectorName: NamePaymentToken, wantKind: KindCredential},
		// Unknown
		{name: "custom detector returns empty", detectorName: DetectorName("custom"), wantKind: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := Finding{DetectorName: tt.detectorName}
			if got := f.Kind(); got != tt.wantKind {
				t.Errorf("Kind() = %q, want %q", got, tt.wantKind)
			}
		})
	}
}
