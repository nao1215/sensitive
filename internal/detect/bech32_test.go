package detect

import (
	"strings"
	"testing"
)

// These finite vectors cover alphabet endpoints that random addresses rarely hit.
func TestBech32Alphabet(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		if got, want := bech32CharIndex(b), strings.IndexByte("qpzry9x8gf2tvdw0s3jn54khce6mua7l", b); got != want {
			t.Fatalf("bech32 %x: %d != %d", b, got, want)
		}
	}
	for _, s := range []string{"az", "AZ", "aZ", "Az", "09"} {
		if isBech32ConsistentCase(s) != (s == strings.ToLower(s) || s == strings.ToUpper(s)) {
			t.Fatalf("bech32 case %q", s)
		}
	}
}
