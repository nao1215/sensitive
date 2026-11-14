package detector_test

import (
	"fmt"
	"strings"
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
		{detector.NewGitHubToken(), "ghp_" + strings.Repeat("a", 36)},
		{detector.NewGoogleAPIKey(), "AIza" + strings.Repeat("A", 35)},
		{detector.NewSlackToken(), "xoxb-" + strings.Repeat("a", 30)},
		{detector.NewSWIFTBIC(), "DEUTDEFF500"},
		{detector.NewIPAddr(), "2001:db8::1"},
		{detector.NewJPPhone(), "09012345678"},
		{detector.NewPAN(), "4532015112830366"},
		{detector.NewMyNumber(), "123456789018"},
		{detector.NewABARouting(), "021000021"},
		{detector.NewJPPhone(), "090-1234-5678"},
		{detector.NewUKSortCode(), "12-34-56"},
		{detector.NewIPAddr(), "192.168.0.1"},
		{detector.NewBTC(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{detector.NewBTC(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{detector.NewETH(), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{detector.NewAWSKey(), "AKIAIOSFODNN7EXAMPLE"},
		{detector.NewIBAN(), "GB82WEST12345698765432"},
		{detector.NewJWT(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
	}
	for _, sample := range samples {
		for _, prefix := range []string{"v%3D", "v%3d", "v%20", "v%09", "v%22", "v%3A", "", " "} {
			t.Run(string(sample.d.Name())+prefix, func(t *testing.T) {
				t.Parallel()
				got := sample.d.Scan([]byte(prefix + sample.raw))
				if len(got) != 1 || got[0].RawValue != sample.raw || got[0].Start != len(prefix) || got[0].End != len(prefix)+len(sample.raw) {
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

func TestEncodedSeparatorBytes(t *testing.T) {
	t.Parallel()
	const separators = " \t\n\r\"'()[]{}:,;=&?"
	for value := range 256 {
		for _, format := range []string{"%%%02x", "%%%02X"} {
			escape := fmt.Sprintf(format, value)
			want := strings.ContainsRune(separators, rune(value))
			for _, prefix := range []string{"", "a", "prefix"} {
				input := []byte(prefix + escape + "AKIAIOSFODNN7EXAMPLE")
				if got := len(detector.NewAWSKey().Scan(input)) == 1; got != want {
					t.Errorf("escape %q: got %v want %v", escape, got, want)
				}
			}
		}
	}
	for _, s := range []string{"%G0", "%0G", "%:0", "%g0", "%0g", "x3D", "%3"} {
		if len(detector.NewAWSKey().Scan([]byte(s+"AKIAIOSFODNN7EXAMPLE"))) != 0 {
			t.Errorf("invalid escape %q relaxed a word boundary", s)
		}
	}
}

func TestEncodedBoundaryKeepsOriginalBytes(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"v%３D", "v%３d"} {
		if got := detector.NewABARouting().Scan([]byte(prefix + "021000021")); len(got) != 0 {
			t.Fatalf("malformed original escape accepted: %q", prefix)
		}
	}
}

func TestBitcoinIdentifierBoundaries(t *testing.T) {
	t.Parallel()
	raw := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	for _, value := range []string{"_" + raw, raw + "_", "a" + raw, raw + "a"} {
		if len(detector.NewBTC().Scan([]byte(value))) != 0 {
			t.Fatalf("embedded address accepted: %s", value)
		}
	}
	for _, value := range []string{raw, strings.ToUpper(raw)} {
		if got := detector.NewBTC().Scan([]byte(value)); len(got) != 1 || got[0].RawValue != value {
			t.Fatal("consistent-case address rejected")
		}
	}
}
