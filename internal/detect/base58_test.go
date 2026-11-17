package detect

import (
	"strings"
	"testing"
)

// These finite vectors cover alphabet endpoints that random addresses rarely hit.
func TestBase58Alphabet(t *testing.T) {
	t.Parallel()
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for n := range 256 {
		b := byte(n)
		if got, want := base58CharIndex(b), strings.IndexByte(alphabet, b); got != want {
			t.Fatalf("base58 %x: %d != %d", b, got, want)
		}
		if isBase58Char(b) != strings.ContainsRune(alphabet, rune(b)) {
			t.Fatalf("base58 byte %x", b)
		}
	}
	for _, s := range []string{"0", "O", "I", "l", "!"} {
		if _, ok := base58Decode(s); ok {
			t.Fatalf("invalid base58 %q", s)
		}
	}
}

func TestBase58ChecksumRejectsShortInput(t *testing.T) {
	t.Parallel()
	if validateBase58Checksum([]byte{1, 2, 3, 4}) {
		t.Fatal("short checksum accepted")
	}
}
