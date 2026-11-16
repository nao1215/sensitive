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

func TestBusinessLabelsAtFieldBoundaries(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"[Order ID: ", ";invoice=", "\ntracking: ", "{\"serial\":\""} {
		got := NewPAN().Scan([]byte(prefix + samplePAN))
		if len(got) != 1 || got[0].Confidence != .4 {
			t.Fatal(prefix, got)
		}
	}
}
