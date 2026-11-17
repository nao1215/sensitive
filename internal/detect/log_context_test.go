package detect

import (
	"testing"
)

func TestEntropyPunctuationAndModuleBoundaries(t *testing.T) {
	t.Parallel()
	// #nosec G101 -- Synthetic mixed-alphabet input for the entropy boundary test.
	const token = "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg"
	for _, tc := range []struct {
		text string
		want int
	}{
		{"." + token, 1},
		{token + ".", 1},
		{"[." + token + ".]", 1},
		{"a." + token, 0},
		{token + ".a", 0},
	} {
		if got := (&HighEntropy{}).Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("punctuation versus module component %q: %v", tc.text, got)
		}
	}
}

func TestNumberHostnameAndSentenceBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want int
	}{
		{"1.111111111118", 0},
		{"No.111111111118", 1},
		{"_-111111111118", 0},
		{"111111111118.example.test", 0},
		{"111111111118-a.example.test", 0},
		{"111111111118.", 1},
		{"111111111118. end", 1},
		{"111111111118-host!.text", 1},
		{"111111111118-note", 1},
	} {
		if got := NewMyNumber().Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("numeric context %q: %v", tc.text, got)
		}
	}
}

func TestJavaIdentityTokenBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want int
	}{
		{"token=A@a", 0},
		{"token=Z@1234567890abcdef", 0},
		{"token=A@1234567890abcdef0", 1},
		{`token="A@a"`, 1},
		{`token='Z@a'`, 1},
		{"token=a@a", 1},
		{"token=@a", 1},
	} {
		if got := (&Credential{}).Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("Java identity versus opaque string %q: %v", tc.text, got)
		}
	}
}

func TestLogContextPreservesStandaloneValues(t *testing.T) {
	t.Parallel()
	for _, text := range []string{`token=Example@zz`, `token="Example@a"`, `token=Example@12345678901234567`, `token=example@a`, `token=Foo!@a`, `token=@a`, `token=Example@`} {
		if len((&Credential{}).Scan([]byte(text))) != 1 {
			t.Errorf("string token lost: %s", text)
		}
	}
	for _, text := range []string{"111111111118", "111111111118-note", "111111111118-", "111111111118;"} {
		if len(NewMyNumber().Scan([]byte(text))) != 1 {
			t.Errorf("standalone number lost: %s", text)
		}
	}
}

func TestUUIDGroupsAreNotIdentifiers(t *testing.T) {
	t.Parallel()
	const aadhaar DetectorName = "in_aadhaar"
	detectors := map[DetectorName]Detector{NamePAN: NewPAN(), NameMyNumber: NewMyNumber(), aadhaar: NewCountry(aadhaar), NameSWIFTBIC: NewSWIFTBIC()}
	for _, tc := range []struct {
		detector DetectorName
		text     string
		want     int
	}{
		{NamePAN, `"auditID":"41111111-1111-1111-a8d9-745602ee7096"`, 0},
		{NamePAN, `"auditID":"41111111-1111-1111"`, 1},
		{NameMyNumber, `"eventID":"ea7648f5-850d-44c4-8e60-111111111118"`, 0},
		{NameMyNumber, `"eventID":"508C931C-1111-1111-1118-E2B14B46B2F7"`, 0},
		{NameMyNumber, `req-ea7648f5-850d-44c4-8e60-111111111118-retry`, 0},
		{NameMyNumber, `"eventID":"ea7648f-850d-44c4-8e60-111111111118"`, 1},
		{NameMyNumber, `"eventID":"8e60-111111111118"`, 1},
		{aadhaar, `"requestID":"1f41f897-dafe-427b-af4e-234567890124"`, 0},
		{aadhaar, `"requestID":"234567890124"`, 1},
		{NameSWIFTBIC, `"auditID":"abcdca12-5186-4865-bead-87b827e025f7"`, 0},
		{NameSWIFTBIC, `"auditID":"abcdca12-5186"`, 1},
	} {
		if got := detectors[tc.detector].Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("%s %q: got %v, want %d findings", tc.detector, tc.text, got, tc.want)
		}
	}
}

func TestCanonicalUUIDLayout(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"ea7648f5-850d-44c4-8e60-111111111118", true},
		{"ea7648f5-850d-44c4-8e60-11111111111", false},
		{"xea7648f5-850d-44c4-8e60-111111111118", false},
		{"ea7648f5-850d-44c4-8e60-111111111118x", false},
		{"ea7648f5x850d-44c4-8e60-111111111118", false},
		{"ea7648g5-850d-44c4-8e60-111111111118", false},
	} {
		at := 0
		if tc.text[0] == 'x' {
			at = 1
		}
		if got := canonicalUUID([]byte(tc.text), at); got != tc.want {
			t.Errorf("%q at %d: got %v, want %v", tc.text, at, got, tc.want)
		}
	}
}
