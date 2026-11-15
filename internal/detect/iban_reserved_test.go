package detect

import "testing"

func TestIBANReservedCheckDigits(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"DE00100100100000000067", "DE01100100100000000049", "DE99100100100000000031"} {
		t.Run(value[:4], func(t *testing.T) {
			t.Parallel()
			if got := NewIBAN().Scan([]byte(value)); len(got) != 0 {
				t.Fatalf("reserved check digits accepted: %v", got)
			}
		})
	}
}
