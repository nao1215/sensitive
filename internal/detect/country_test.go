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

const (
	ssnName     DetectorName = "us_ssn"
	sinName     DetectorName = "ca_sin"
	nhsName     DetectorName = "uk_nhs"
	aadhaarName DetectorName = "in_aadhaar"
	cpfName     DetectorName = "br_cpf"
)

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
		{sinName, "member id 130-692-544", 0},
		{sinName, "sin id 130-692-544", 1},
		{nhsName, "order no 943 476 5919", 0},
		{nhsName, "nhs id 943 476 5919", 1},
		{aadhaarName, "aadhaar id 2345 6789 0124", 1},
		{aadhaarName, "aadhar id 2345 6789 0124", 1},
		{cpfName, "cpf id 529.982.247-25", 1},
		{cpfName, "account 529.982.247-25", 0},
		{ssnName, "identity=123456789", 0},
		{ssnName, "identity=123-45-6789", 1},
		{ssnName, "ssn=123456789", 1},
		{sinName, "social insurance number 130692544", 1},
		{sinName, "subject 130692544", 0},
		{nhsName, "nhs 9434765919", 1},
		{nhsName, "patient 9434765919", 0},
		{aadhaarName, "aadhaar 234567890124", 1},
		{cpfName, "subject 52998224725", 1},
	} {
		if got := len(NewCountry(tc.name).Scan([]byte(tc.input))); got != tc.want {
			t.Errorf("%s %q: %d findings, want %d", tc.name, tc.input, got, tc.want)
		}
	}
	for _, tc := range []struct {
		name  DetectorName
		label string
	}{{"uk_nino", "nino"}, {"in_pan", "pan"}, {"br_cnpj", "cnpj"}, {"cn_resident_id", "resident"}, {"kr_rrn", "rrn"}} {
		if labels := countryFamilies()[tc.name].labels; labels[0] != tc.label {
			t.Errorf("%s labels %q, want %q first", tc.name, labels, tc.label)
		}
	}
}
