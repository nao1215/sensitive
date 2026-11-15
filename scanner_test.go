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
