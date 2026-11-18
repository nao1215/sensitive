package detect

import "testing"

func TestCountryConstructorRejectsUnsupportedName(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("unsupported country accepted")
		}
	}()
	NewCountry("unsupported")
}

func TestCountryRejectedBoundaries(t *testing.T) {
	t.Parallel()
	if _, _, ok := countryCandidate([]byte("A"), 0, "X"); ok {
		t.Fatal("non-check digit accepted")
	}
}

const ssnName DetectorName = "us_ssn"

func TestCountryRecordLabels(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  DetectorName
		input string
		want  int
	}{
		{ssnName, "user_id=123456789", 0},
		{ssnName, "ssn_id=123456789", 1},
		{ssnName, "social security number 123-45-6789", 1},
		{"us_itin", "taxpayer id 912-70-1234", 1},
		{"ca_sin", "member id 130-692-544", 0},
		{"ca_sin", "sin id 130-692-544", 1},
		{"uk_nhs", "order no 943 476 5919", 0},
		{"uk_nhs", "nhs id 943 476 5919", 1},
		{"in_aadhaar", "aadhaar id 2345 6789 0124", 1},
		{"in_aadhaar", "aadhar id 2345 6789 0124", 1},
		{"br_cpf", "cpf id 529.982.247-25", 1},
		{"br_cpf", "account 529.982.247-25", 0},
	} {
		if got := len(NewCountry(tc.name).Scan([]byte(tc.input))); got != tc.want {
			t.Errorf("%s %q: %d findings, want %d", tc.name, tc.input, got, tc.want)
		}
	}
	for _, tc := range []struct {
		name  DetectorName
		label string
	}{{"uk_nino", "nino"}, {"in_pan", "pan"}, {"br_cnpj", "cnpj"}, {"cn_resident_id", "resident"}, {"kr_rrn", "rrn"}} {
		if _, labels := countryLayouts(tc.name); labels[0] != tc.label {
			t.Errorf("%s labels %q, want %q first", tc.name, labels, tc.label)
		}
	}
}
