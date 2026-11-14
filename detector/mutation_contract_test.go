package detector

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

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

// Compare window extraction to a whole-input token oracle; truncated tokens
// must never turn into plausible CVVs, account numbers, or merchant IDs.
func TestContextWindowContract(t *testing.T) {
	t.Parallel()
	for _, alpha := range []bool{false, true} {
		for width := 1; width <= 22; width++ {
			value := strings.Repeat("7", width)
			if alpha {
				value = strings.Repeat("A", width)
			}
			data := []byte("...." + value + "....")
			for pos := 0; pos <= len(data); pos++ {
				for radius := 0; radius <= len(data); radius++ {
					lo := max(0, pos-radius)
					hi := min(len(data), pos+radius)
					want := width >= 3 && width <= 19 && lo <= 4 && hi >= 4+width
					if alpha {
						got := extractAlphaNumNear(data, pos, radius, 3, 19)
						if (len(got) == 1) != want || len(got) > 1 {
							t.Fatalf("alpha width=%d pos=%d radius=%d: %+v", width, pos, radius, got)
						}
					} else {
						got := extractDigitsNear(data, pos, radius, 3, 19)
						if (len(got) == 1) != want || len(got) > 1 {
							t.Fatalf("digits width=%d pos=%d radius=%d: %+v", width, pos, radius, got)
						}
					}
				}
			}
		}
	}
}

func TestCredentialBoundaryContract(t *testing.T) {
	t.Parallel()
	for _, d := range []Detector{NewAWSKey(), NewGitHubToken(), NewGoogleAPIKey(), NewSlackToken(), NewETH()} {
		raw := map[DetectorName]string{NameAWSKey: "AKIAIOSFODNN7EXAMPLE", NameGitHubToken: "ghp_" + strings.Repeat("a", 36), NameGoogleAPIKey: "AIza" + strings.Repeat("a", 35), NameSlackToken: "xoxb-" + strings.Repeat("a", 10), NameETH: "0x" + strings.Repeat("a", 40)}[d.Name()]
		for _, b := range []byte("AZaz09_") {
			if d.Name() == NameAWSKey && b == '_' {
				continue
			}
			for _, text := range []string{string(b) + raw, raw + string(b)} {
				// Variable-length Slack tokens absorb a valid suffix by design.
				if d.Name() == NameSlackToken && strings.HasPrefix(text, raw) && b != '_' {
					continue
				}
				if got := d.Scan([]byte(text)); len(got) != 0 {
					t.Fatalf("%s boundary %q: %+v", d.Name(), text, got)
				}
			}
		}
	}
}

func TestABAChecksumAndDistrictContract(t *testing.T) {
	t.Parallel()
	for prefix := range 100 {
		raw := []byte{byte('0' + prefix/10), byte('0' + prefix%10), '1', '2', '3', '4', '5', '6', '0'}
		sum := 0
		for i, b := range raw[:8] {
			sum += int(b-'0') * []int{3, 7, 1}[i%3]
		}
		raw[8] = byte('0' + (10-sum%10)%10)
		valid := prefix >= 1 && prefix <= 12 || prefix >= 21 && prefix <= 32 || prefix >= 61 && prefix <= 72 || prefix == 80
		if (len(NewABARouting().Scan(raw)) == 1) != valid {
			t.Fatalf("district %s", raw)
		}
		if !valid {
			continue
		}
		for i := range raw {
			bad := bytes.Clone(raw)
			bad[i] = '0' + (bad[i]-'0'+1)%10
			if validateABAChecksum(bad) {
				t.Fatalf("checksum position %d", i)
			}
		}
	}
}

// These finite vectors cover alphabet endpoints that random addresses rarely hit.
func TestEncodingAlphabetVectors(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		if got, want := base58CharIndex(b), strings.IndexByte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", b); got != want {
			t.Fatalf("base58 %x: %d != %d", b, got, want)
		}
		if got, want := bech32CharIndex(b), strings.IndexByte("qpzry9x8gf2tvdw0s3jn54khce6mua7l", b); got != want {
			t.Fatalf("bech32 %x: %d != %d", b, got, want)
		}
	}
	for _, s := range []string{"0", "O", "I", "l", "!"} {
		if _, ok := base58Decode(s); ok {
			t.Fatalf("invalid base58 %q", s)
		}
	}
	for _, s := range []string{"az", "AZ", "aZ", "Az", "09"} {
		lower, upper := strings.ToLower(s), strings.ToUpper(s)
		if isBech32ConsistentCase(s) != (s == lower || s == upper) {
			t.Fatalf("bech32 case %q", s)
		}
		if toLowerString(s) != lower {
			t.Fatalf("lowercase %q", s)
		}
	}
}

// Enumerate the date-like ambiguity edges independently as decimal examples.
func TestSortCodeDateAmbiguityVectors(t *testing.T) {
	t.Parallel()
	for _, first := range []int{0, 1, 9, 10, 30, 31, 32, 99} {
		for _, month := range []int{0, 1, 9, 10, 12, 13, 99} {
			for _, last := range []int{0, 1, 9, 10, 30, 31, 32, 99} {
				want := month >= 1 && month <= 12 && (first >= 1 && first <= 31 || last >= 1 && last <= 31)
				digits := fmt.Sprintf("%02d%02d%02d", first, month, last)
				got := isSortCodeDateLike(digits[0], digits[1], digits[2], digits[3], digits[4], digits[5])
				if got != want {
					t.Fatalf("date ambiguity %02d-%02d-%02d", first, month, last)
				}
			}
		}
	}
}
