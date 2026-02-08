package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestFinding_Is(t *testing.T) {
	t.Parallel()

	f := detector.Finding{DetectorName: detector.NamePAN}

	if !f.Is(detector.NamePAN) {
		t.Error("Is(NamePAN) should return true for a PAN finding")
	}
	if f.Is(detector.NameEmail) {
		t.Error("Is(NameEmail) should return false for a PAN finding")
	}
}

func TestFinding_IsXXX(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		finding  detector.Finding
		check    func(detector.Finding) bool
		wantTrue bool
	}{
		{"IsPAN true", detector.Finding{DetectorName: detector.NamePAN}, detector.Finding.IsPAN, true},
		{"IsPAN false", detector.Finding{DetectorName: detector.NameEmail}, detector.Finding.IsPAN, false},
		{"IsEmail true", detector.Finding{DetectorName: detector.NameEmail}, detector.Finding.IsEmail, true},
		{"IsEmail false", detector.Finding{DetectorName: detector.NamePAN}, detector.Finding.IsEmail, false},
		{"IsJPPhone true", detector.Finding{DetectorName: detector.NameJPPhone}, detector.Finding.IsJPPhone, true},
		{"IsMyNumber true", detector.Finding{DetectorName: detector.NameMyNumber}, detector.Finding.IsMyNumber, true},
		{"IsJWT true", detector.Finding{DetectorName: detector.NameJWT}, detector.Finding.IsJWT, true},
		{"IsAWSKey true", detector.Finding{DetectorName: detector.NameAWSKey}, detector.Finding.IsAWSKey, true},
		{"IsIBAN true", detector.Finding{DetectorName: detector.NameIBAN}, detector.Finding.IsIBAN, true},
		{"IsIPAddr true", detector.Finding{DetectorName: detector.NameIPAddr}, detector.Finding.IsIPAddr, true},
		{"IsSWIFTBIC true", detector.Finding{DetectorName: detector.NameSWIFTBIC}, detector.Finding.IsSWIFTBIC, true},
		{"IsABARouting true", detector.Finding{DetectorName: detector.NameABARouting}, detector.Finding.IsABARouting, true},
		{"IsUKSortCode true", detector.Finding{DetectorName: detector.NameUKSortCode}, detector.Finding.IsUKSortCode, true},
		{"IsCVV true", detector.Finding{DetectorName: detector.NameCVV}, detector.Finding.IsCVV, true},
		{"IsCardExpiry true", detector.Finding{DetectorName: detector.NameCardExpiry}, detector.Finding.IsCardExpiry, true},
		{"IsPaymentToken true", detector.Finding{DetectorName: detector.NamePaymentToken}, detector.Finding.IsPaymentToken, true},
		{"IsBankAccount true", detector.Finding{DetectorName: detector.NameBankAccount}, detector.Finding.IsBankAccount, true},
		{"IsACHTrace true", detector.Finding{DetectorName: detector.NameACHTrace}, detector.Finding.IsACHTrace, true},
		{"IsMerchantID true", detector.Finding{DetectorName: detector.NameMerchantID}, detector.Finding.IsMerchantID, true},
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
		name   string
		f      detector.Finding
		expect func(detector.Finding) bool
	}{
		{
			name: "SWIFTBICDetail",
			f: detector.Finding{
				DetectorName: detector.NameSWIFTBIC,
				Detail:       &detector.SWIFTBICDetail{BankCode: "BOFA"},
			},
			expect: func(f detector.Finding) bool { _, ok := f.SWIFTBICDetail(); return ok },
		},
		{
			name: "ABARoutingDetail",
			f: detector.Finding{
				DetectorName: detector.NameABARouting,
				Detail:       &detector.ABARoutingDetail{FederalReserveDistrict: "02-New York"},
			},
			expect: func(f detector.Finding) bool { _, ok := f.ABARoutingDetail(); return ok },
		},
		{
			name: "UKSortCodeDetail",
			f: detector.Finding{
				DetectorName: detector.NameUKSortCode,
				Detail:       &detector.UKSortCodeDetail{FormattedValue: "12-34-56"},
			},
			expect: func(f detector.Finding) bool { _, ok := f.UKSortCodeDetail(); return ok },
		},
		{
			name: "CVVDetail",
			f: detector.Finding{
				DetectorName: detector.NameCVV,
				Detail:       &detector.CVVDetail{DigitCount: 3},
			},
			expect: func(f detector.Finding) bool { _, ok := f.CVVDetail(); return ok },
		},
		{
			name: "CardExpiryDetail",
			f: detector.Finding{
				DetectorName: detector.NameCardExpiry,
				Detail:       &detector.CardExpiryDetail{Month: "12", Year: "25"},
			},
			expect: func(f detector.Finding) bool { _, ok := f.CardExpiryDetail(); return ok },
		},
		{
			name: "PaymentTokenDetail",
			f: detector.Finding{
				DetectorName: detector.NamePaymentToken,
				Detail:       &detector.PaymentTokenDetail{Provider: "Stripe"},
			},
			expect: func(f detector.Finding) bool { _, ok := f.PaymentTokenDetail(); return ok },
		},
		{
			name: "BankAccountDetail",
			f: detector.Finding{
				DetectorName: detector.NameBankAccount,
				Detail:       &detector.BankAccountDetail{Language: "en"},
			},
			expect: func(f detector.Finding) bool { _, ok := f.BankAccountDetail(); return ok },
		},
		{
			name: "ACHTraceDetail",
			f: detector.Finding{
				DetectorName: detector.NameACHTrace,
				Detail:       &detector.ACHTraceDetail{ODFIRoutingNumber: "02100002"},
			},
			expect: func(f detector.Finding) bool { _, ok := f.ACHTraceDetail(); return ok },
		},
		{
			name: "MerchantIDDetail",
			f: detector.Finding{
				DetectorName: detector.NameMerchantID,
				Detail:       &detector.MerchantIDDetail{IDType: "merchant"},
			},
			expect: func(f detector.Finding) bool { _, ok := f.MerchantIDDetail(); return ok },
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
		confidence float64
		wantLevel  detector.ConfidenceLevel
		wantStr    string
	}{
		{"high confidence (1.0)", 1.0, detector.ConfidenceHigh, "high"},
		{"high confidence (0.8)", 0.8, detector.ConfidenceHigh, "high"},
		{"medium confidence (0.79)", 0.79, detector.ConfidenceMedium, "medium"},
		{"medium confidence (0.4)", 0.4, detector.ConfidenceMedium, "medium"},
		{"low confidence (0.39)", 0.39, detector.ConfidenceLow, "low"},
		{"low confidence (0.0)", 0.0, detector.ConfidenceLow, "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := detector.Finding{Confidence: tt.confidence}
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
		level detector.ConfidenceLevel
		want  string
	}{
		{detector.ConfidenceLow, "low"},
		{detector.ConfidenceMedium, "medium"},
		{detector.ConfidenceHigh, "high"},
		{detector.ConfidenceLevel(99), "unknown"},
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
