package embargo_test

import (
	"testing"

	"github.com/nao1215/embargo"
)

func TestScannerRecognitionRegressions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind        embargo.Kind
		text, value string
	}{
		{kind: embargo.KindUKSortCode, text: "sort code: 12 34 56", value: "12 34 56"},
		{kind: embargo.KindBankAccount, text: "acct no: 12345678", value: "12345678"},
		{kind: embargo.KindPAN, text: "card ４５３２０１５１１２８３０３６６", value: "４５３２０１５１１２８３０３６６"},
		{kind: embargo.KindJPPhone, text: "phone ０９０１２３４５６７８", value: "０９０１２３４５６７８"},
		{kind: embargo.KindCVV, text: "SECURITY CODE: 123", value: "123"},
		{kind: embargo.KindIBAN, text: "IBAN: PK36SCBL0000001123456702", value: "PK36SCBL0000001123456702"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			t.Parallel()
			got := embargo.NewScanner(embargo.WithKinds(tc.kind)).ScanString(tc.text)
			if len(got) != 1 || tc.text[got[0].Start:got[0].End] != tc.value {
				t.Fatalf("%v", got)
			}
		})
	}
	if got := embargo.NewScanner(embargo.WithKinds(embargo.KindIPAddr)).ScanString("2001:db8::1Z"); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestDocumentedConfidenceBoundary(t *testing.T) {
	t.Parallel()
	const documentedEmail = "alice@example.com"
	for _, fixture := range []struct {
		text      string
		kind      embargo.Kind
		threshold float64
	}{
		{documentedEmail, embargo.KindEmail, 1},
		{"alice@example.zzzz", embargo.KindEmail, 0.8},
		{"alice@ex..ample.com", embargo.KindEmail, 0.9},
		{"eyJ4IjoxfQ.e30.c2ln", embargo.KindJWT, 0.9},
	} {
		t.Run(fixture.text, func(t *testing.T) {
			t.Parallel()
			scanner := embargo.NewScanner(embargo.WithKinds(fixture.kind), embargo.WithMinConfidence(fixture.threshold))
			findings := scanner.ScanString(fixture.text)
			if len(findings) != 1 || findings[0].Confidence != fixture.threshold || embargo.Mask(fixture.text, findings) == fixture.text {
				t.Fatalf("inclusive threshold %g lost or changed score: %v", fixture.threshold, findings)
			}
		})
	}
}
