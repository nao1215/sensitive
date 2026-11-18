package detect

import (
	"testing"
)

func TestBusinessIdentifiersHaveLowerConfidence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d     Detector
		value string
	}{
		{NewPAN(), samplePAN}, {NewMyNumber(), sampleMyNumber}, {NewJPPhone(), sampleMobile},
	} {
		for _, label := range []string{"Order ID: ", "invoice_ref = ", "tracking_serial = ", "Version: ", "build: ", "Shipment ID: ", "?order=", "&invoice=", "注文番号: ", "お客様の品番="} {
			got := tc.d.Scan([]byte(label + tc.value))
			if tc.d.Name() == NameMyNumber {
				// An identifier label rules a My Number out instead of lowering it.
				if len(got) != 0 {
					t.Errorf("%s %s: %+v", tc.d.Name(), label, got)
				}
				continue
			}
			if len(got) != 1 || got[0].Confidence >= 0.7 {
				t.Errorf("%s %s: %+v", tc.d.Name(), label, got)
			}
		}
		for _, label := range []string{"card: ", "phone: ", "My Number: ", "order completed; card: ", "invoice\n"} {
			got := tc.d.Scan([]byte(label + tc.value))
			if len(got) != 1 || got[0].Confidence < 0.7 {
				t.Errorf("positive %s %s: %+v", tc.d.Name(), label, got)
			}
		}
	}
}

func TestBusinessLabelsAtFieldBoundaries(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"[Order ID: ", ";invoice=", "\ntracking: ", "{\"serial\":\""} {
		got := NewPAN().Scan([]byte(prefix + samplePAN))
		if len(got) != 1 || got[0].Confidence != .4 {
			t.Fatal(prefix, got)
		}
	}
}

func TestMyNumberIdentifierLabels(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		prefix string
		found  bool
	}{
		{"", true},
		{"My Number: ", true},
		{"my_number=", true},
		{"individual number ", true},
		{"マイナンバー: ", true},
		{"個人番号：", true},
		{"phone: ", true},
		{`{"accountId":"`, false},
		{`{"recipientAccountId":"`, false},
		{"aws_account_id=", false},
		{"AssumeRole for account ", false},
		{"user_id=", false},
		{"tracking ", false},
		{"customer number ", false},
		{"注文番号: ", false},
		{"会員番号 ", false},
		{"注文ID=", false},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			t.Parallel()
			if got := NewMyNumber().Scan([]byte(tc.prefix + sampleMyNumber)); (len(got) == 1) != tc.found {
				t.Fatalf("Scan(%q) = %+v, want found %v", tc.prefix+sampleMyNumber, got, tc.found)
			}
		})
	}
}
