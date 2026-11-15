package detect

import "testing"

func TestBusinessIdentifiersHaveLowerConfidence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d     Detector
		value string
	}{
		{NewPAN(), "4242424242424242"}, {NewMyNumber(), "123456789018"}, {NewJPPhone(), "090-1234-5678"},
	} {
		for _, label := range []string{"Order ID: ", "invoice_ref = ", "tracking_serial = ", "Version: ", "build: ", "Shipment ID: ", "?order=", "&invoice="} {
			got := tc.d.Scan([]byte(label + tc.value))
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

func TestMyNumberIdentifierBoundaries(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"_123456789018", "123456789018_suffix", "123456789018x", "x123456789018"} {
		if got := NewMyNumber().Scan([]byte(text)); len(got) != 0 {
			t.Errorf("identifier fragment %q: %+v", text, got)
		}
	}
}
