package detect

import (
	"encoding/hex"
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
		{d: NewEmail(), raw: "tanaka@example.com"},
		{d: NewGitHubToken(), raw: "ghp_" + strings.Repeat("a", 36)},
		{d: NewGoogleAPIKey(), raw: "AIza" + strings.Repeat("A", 35)},
		{d: NewSlackToken(), raw: "xoxb-" + strings.Repeat("a", 30)},
		{d: NewSWIFTBIC(), raw: "DEUTDEFF500"},
		{d: NewIPAddr(), raw: "2001:db8::1"},
		{d: NewJPPhone(), raw: "09012345678"},
		{d: NewPAN(), raw: "4532015112830366"},
		{d: NewMyNumber(), raw: sampleMyNumber},
		{d: NewABARouting(), raw: "021000021"},
		{d: NewJPPhone(), raw: sampleMobile},
		{d: NewUKSortCode(), raw: sampleSortCode},
		{d: NewIPAddr(), raw: "192.168.0.1"},
		{d: NewBTC(), raw: sampleBase58},
		{d: NewBTC(), raw: sampleBech32},
		{d: NewETH(), raw: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{d: NewAWSKey(), raw: sampleAccessKey}, // #nosec G101 -- AWS publishes this example access key; it is not an authentication credential.
		{d: NewIBAN(), raw: sampleIBAN},
		{d: NewJWT(), raw: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
	}
	for _, sample := range samples {
		for _, prefix := range []string{"v%3D", "v%3d", "v%20", "v%09", "v%22", "v%3A", "", " "} {
			t.Run(string(sample.d.Name())+prefix, func(t *testing.T) {
				t.Parallel()
				got := sample.d.Scan([]byte(prefix + sample.raw + "\n" + sample.raw))
				if len(got) != 2 || got[0].RawValue != sample.raw || got[0].Start != len(prefix) || got[0].End != len(prefix)+len(sample.raw) || got[1].RawValue != sample.raw || got[1].Start != len(prefix)+len(sample.raw)+1 || got[1].End != len(prefix)+2*len(sample.raw)+1 {
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
			// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
			raw := map[DetectorName]string{NameAWSKey: sampleAccessKey, NameIBAN: sampleIBAN, NameETH: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"}[d.Name()]
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
				input := []byte(prefix + escape + sampleAccessKey)
				if got := len(NewAWSKey().Scan(input)) == 1; got != want {
					t.Errorf("escape %q: got %v want %v", escape, got, want)
				}
			}
		}
	}
	for _, s := range []string{"%G0", "%0G", "%:0", "%g0", "%0g", "x3D", "%3"} {
		if len(NewAWSKey().Scan([]byte(s+sampleAccessKey))) != 0 {
			t.Errorf("invalid escape %q relaxed a word boundary", s)
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
	raw := sampleBech32
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

// Exhaustive byte alphabets protect endpoint characters as well as interior ones.
func TestBoundaryAlphabetContract(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		alnum := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", rune(b))
		if isASCIIAlphaNum(b) != alnum {
			t.Fatalf("ASCII alphabet %x", b)
		}
		if isTokenByte(b) != (alnum || b == '_' || b == '-') {
			t.Fatalf("token alphabet %x", b)
		}
		decoded, err := hex.DecodeString("0" + string(b))
		v, ok := boundaryHex(b)
		if ok != (err == nil) || ok && v != decoded[0] {
			t.Fatalf("hex alphabet %x", b)
		}
	}
	for n := range 256 {
		escaped := "v%" + strings.ToUpper(hex.EncodeToString([]byte{byte(n)}))
		want := strings.ContainsRune(" \t\n\r\"'()[]{}:,;=&?", rune(n))
		if encodedSeparatorBefore([]byte(escaped), len(escaped)) != want {
			t.Fatalf("encoded boundary %q", escaped)
		}
	}
}
