package detect

import (
	"testing"
)

const userIDLabel = "user_id="

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
		{userIDLabel, false},
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

func TestRecordLabeled(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]bool{
		userIDLabel:           true,
		"order number: ":      true,
		"注文番号 ":               true,
		"customerID: ":        true,
		"routing code: ":      false,
		"ssn_id=":             false,
		"social security id ": false,
		"phone number ":       false,
		"value=":              false,
		"":                    false,
	} {
		data := []byte(input + "123")
		if got := recordLabeled(data, len(input), "routing", "ssn", "security"); got != want {
			t.Errorf("recordLabeled(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestRecordConfidence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d     Detector
		label string
		want  float64
	}{
		{NewPAN(), userIDLabel, ambiguousConfidence},
		{NewPAN(), "customer number: ", ambiguousConfidence},
		{NewPAN(), "card_id=", 1},
		{NewPAN(), "credit card number: ", 1},
		{NewPAN(), "カード番号: ", 1},
		{NewJPPhone(), "user_id: ", ambiguousConfidence},
		{NewJPPhone(), "phone_id: ", 0.9},
		{NewJPPhone(), "電話番号: ", 0.9},
		{NewJPPhone(), "携帯番号=", 0.9},
	} {
		value := samplePAN
		if tc.d.Name() == NameJPPhone {
			value = sampleMobile
		}
		got := tc.d.Scan([]byte(tc.label + value))
		if len(got) != 1 || got[0].Confidence != tc.want {
			t.Errorf("%s %q: %+v, want confidence %v", tc.d.Name(), tc.label, got, tc.want)
		}
	}
}

func TestLabelNames(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]bool{
		"social security number ": true,
		"ssn_ref_no=":             true,
		"ssn a b c=":              false,
		"携帯番号: ":                  true,
		"phones: ":                false,
		"value=":                  false,
		"":                        false,
	} {
		data := []byte(input + "123")
		if got := labelNames(data, len(input), "ssn", "security", "phone", "携帯"); got != want {
			t.Errorf("labelNames(%q) = %v, want %v", input, got, want)
		}
	}
}
