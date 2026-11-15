package detect

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Independent finite alphabets target boundary mutants missed by ordinary prose.
func TestDetectorByteAlphabets(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		alnum := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", rune(b))
		if isLocalPartChar(b) != (alnum || strings.ContainsRune(".+-_", rune(b))) {
			t.Fatalf("local alphabet %x", b)
		}
		if isDomainChar(b) != (alnum || strings.ContainsRune(".-", rune(b))) {
			t.Fatalf("domain alphabet %x", b)
		}
		_, err := hex.DecodeString("0" + string(b))
		if isHexChar(b) != (err == nil) {
			t.Fatalf("hex alphabet %x", b)
		}
		if toLowerASCIIString(string(b)) != string(bytes.ToLower([]byte{b})) && b < 128 {
			t.Fatalf("case endpoint %x", b)
		}
	}
	for _, domain := range []string{"", "a", "-a", "a-b", "a-.b", "a.-b", "a.b", "a..b", ".a", "a."} {
		want := false
		for label := range strings.SplitSeq(domain, ".") {
			want = want || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-")
		}
		// The helper's contract only covers leading '-' and '-' adjacent to dots;
		// trailing domain hyphens are removed by findDomainEnd.
		if hasInvalidLabelBoundary([]byte(domain)) != want {
			t.Fatalf("label boundary %q", domain)
		}
		if hasConsecutiveDots([]byte(domain)) != strings.Contains(domain, "..") {
			t.Fatalf("dots %q", domain)
		}
	}
}

func TestNormalizationIdentityDifferential(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		input := append([]byte("４２４２ "), byte(n))
		for _, data := range [][]byte{input, {byte(n)}, []byte("4242424242424242"), nil} {
			want, indices := NormalizeFullWidthDigits(data)
			got, positions := normalizeDigits(data)
			if !bytes.Equal(got, want) {
				t.Fatal("normalization differs")
			}
			for i := 0; i <= len(got); i++ {
				if originalPosition(positions, i) != indices[i] {
					t.Fatal("position differs")
				}
			}
		}
	}
}
