package detector

import (
	"fmt"
	"strings"
	"testing"
)

func TestEncodedBoundary(t *testing.T) {
	t.Parallel()
	samples := []struct {
		d   Detector
		raw string
	}{
		{NewEmail(), "tanaka@example.com"},
		{NewGitHubToken(), "ghp_" + strings.Repeat("a", 36)},
		{NewGoogleAPIKey(), "AIza" + strings.Repeat("A", 35)},
		{NewSlackToken(), "xoxb-" + strings.Repeat("a", 30)},
		{NewSWIFTBIC(), "DEUTDEFF500"},
		{NewIPAddr(), "2001:db8::1"},
		{NewJPPhone(), "09012345678"},
		{NewPAN(), "4532015112830366"},
		{NewMyNumber(), "123456789018"},
		{NewABARouting(), "021000021"},
		{NewJPPhone(), "090-1234-5678"},
		{NewUKSortCode(), "12-34-56"},
		{NewIPAddr(), "192.168.0.1"},
		{NewBTC(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{NewBTC(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{NewETH(), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{NewAWSKey(), "AKIAIOSFODNN7EXAMPLE"},
		{NewIBAN(), "GB82WEST12345698765432"},
		{NewJWT(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
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
		for _, d := range []Detector{NewAWSKey(), NewIBAN(), NewETH()} {
			raw := map[DetectorName]string{NameAWSKey: "AKIAIOSFODNN7EXAMPLE", NameIBAN: "GB82WEST12345698765432", NameETH: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"}[d.Name()]
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
				input := []byte(prefix + escape + "secret")
				if got := encodedSeparatorBefore(input, len(prefix)+3); got != want {
					t.Errorf("escape %q: got %v want %v", escape, got, want)
				}
			}
		}
	}
	for _, s := range []string{"", "%", "%3", "x3D", "%G0", "%0G", "%/0", "%0/", "%:0", "%0:", "%g0", "%0g"} {
		if encodedSeparatorBefore([]byte(s), len(s)) {
			t.Errorf("invalid escape %q accepted", s)
		}
	}
}

func TestEncodedBoundaryKeepsOriginalBytes(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"v%３D", "v%３d"} {
		if got := NewABARouting().Scan([]byte(prefix + "021000021")); len(got) != 0 {
			t.Fatalf("malformed original escape accepted: %q", prefix)
		}
	}
}

func TestBitcoinIdentifierBoundaries(t *testing.T) {
	t.Parallel()
	raw := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	for _, value := range []string{"_" + raw, raw + "_", "a" + raw, raw + "a"} {
		if len(NewBTC().Scan([]byte(value))) != 0 {
			t.Fatalf("embedded address accepted: %s", value)
		}
	}
	for _, value := range []string{raw, strings.ToUpper(raw)} {
		if got := NewBTC().Scan([]byte(value)); len(got) != 1 || got[0].RawValue != value {
			t.Fatal("consistent-case address rejected")
		}
	}
}
