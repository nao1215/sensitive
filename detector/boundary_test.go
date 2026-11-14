package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestEncodedBoundary(t *testing.T) {
	t.Parallel()
	samples := []struct {
		d   detector.Detector
		raw string
	}{
		{detector.NewEmail(), "tanaka@example.com"},
		{detector.NewETH(), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{detector.NewAWSKey(), "AKIAIOSFODNN7EXAMPLE"},
		{detector.NewIBAN(), "GB82WEST12345698765432"},
		{detector.NewJWT(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
	}
	for _, sample := range samples {
		for _, prefix := range []string{"v%3D", "v%3d", "v%20", "v%09", "v%22"} {
			t.Run(string(sample.d.Name())+prefix, func(t *testing.T) {
				t.Parallel()
				got := sample.d.Scan([]byte(prefix + sample.raw))
				if len(got) != 1 || got[0].RawValue != sample.raw {
					t.Errorf("encoded separator lost raw value: %v", got)
				}
			})
		}
	}
}

func TestEncodedBoundaryRejectsWordAndMalformedEscapes(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"v%41", "v%30", "v%5F", "v%2D", "v%GG", "v%3", "word", "v%FF"} {
		for _, d := range []detector.Detector{detector.NewAWSKey(), detector.NewIBAN(), detector.NewETH()} {
			raw := map[detector.DetectorName]string{detector.NameAWSKey: "AKIAIOSFODNN7EXAMPLE", detector.NameIBAN: "GB82WEST12345698765432", detector.NameETH: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"}[d.Name()]
			if got := d.Scan([]byte(prefix + raw)); len(got) != 0 {
				t.Errorf("%s %s: unexpected match", d.Name(), prefix)
			}
		}
	}
}
