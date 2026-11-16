package embargo

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
)

type rawPercentDetector struct {
	t    *testing.T
	want []byte
}

func (d rawPercentDetector) Scan(data []byte) []Finding {
	d.t.Helper()
	if !bytes.Equal(data, d.want) {
		d.t.Fatal("custom detector did not receive the original escaped bytes")
	}
	return nil
}

//nolint:paralleltest // AllocsPerRun changes GOMAXPROCS while measuring.
func TestNoBuiltinsAvoidsDecodingAllocations(t *testing.T) {
	data := []byte(strings.Repeat("%41", 128))
	for _, scanner := range []*Scanner{
		NewScanner(WithKinds()),
		NewScanner(WithKinds(), WithDetector(rawPercentDetector{t: t, want: data})),
	} {
		if got := testing.AllocsPerRun(100, func() { scanner.Scan(data) }); got != 0 {
			t.Errorf("unused built-in decoding allocated %.0f times", got)
		}
	}
}

func TestPercentEncodedFindings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind          Kind
		prefix, value string
	}{
		{KindEmail, "", "a+b@example.com"},
		{KindBankAccount, "bank account ", "18393904"},
		{KindCardExpiry, "expiry ", "01/28"},
		{KindMerchantID, "merchant ID ", "ZNFBVPHU2BHHFXP"},
		{KindPrivateKeyPEM, "", "-----BEGIN RSA PRIVATE KEY-----"},
		{KindPAN, "", "４２４２４２４２４２４２４２４２"},
		{KindMyNumber, "", "１２３４５６７８９０１８"},
		{KindJPPhone, "", "０９０－１２３４－５６７８"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			t.Parallel()
			value := url.PathEscape(tc.value)
			prefix := "日本語?value=" + url.PathEscape(tc.prefix)
			got := NewScanner(WithKinds(tc.kind)).ScanString(prefix + value + "&ok=true")
			if len(got) != 1 || got[0].Start != len(prefix) || got[0].End != len(prefix)+len(value) {
				t.Fatalf("original offsets: %+v", got)
			}
		})
	}
}

// Random partial escaping checks exact byte ranges after a UTF-8 prefix.
func TestPercentRoundTripOffsets(t *testing.T) {
	t.Parallel()
	// #nosec G404 -- Fixed seed for reproducible synthetic tests.
	rng := rand.New(rand.NewPCG(91, 27))
	scanner := NewScanner(WithKinds(KindEmail))
	for range 2000 {
		raw := fmt.Sprintf("user%d+tag@example.com", rng.IntN(100000))
		var encoded strings.Builder
		for i := range raw {
			if rng.IntN(2) == 0 {
				if _, err := fmt.Fprintf(&encoded, "%%%02X", raw[i]); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := encoded.WriteByte(raw[i]); err != nil {
					t.Fatal(err)
				}
			}
		}
		value := encoded.String()
		prefix := "記録 value="
		decoded, err := url.PathUnescape(value)
		if err != nil || decoded != raw {
			t.Fatal("oracle")
		}
		got := scanner.ScanString(prefix + value + ";")
		if len(got) != 1 || got[0].Start != len(prefix) || got[0].End != len(prefix)+len(value) {
			t.Fatalf("round trip %q: %+v", value, got)
		}
	}
}

func TestPercentDecodingPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ input, want string }{
		{"a+b", "a+b"}, {"%2520", "%20"}, {"%x1%41%", "%x1A%"}, {"%0", "%0"}, {"%41%0", "A%0"}, {"%00%FF", "\x00\xff"},
	} {
		data, positions := decodePercent([]byte(tc.input))
		if string(data) != tc.want {
			t.Fatalf("decode %q: %q", tc.input, data)
		}
		if positions != nil {
			if len(positions) != len(data)+1 {
				t.Fatal("map length")
			}
			if positions[len(data)] != len(tc.input) {
				t.Fatal("sentinel")
			}
		}
	}
	for b := range 256 {
		escaped := fmt.Sprintf("%%%02x", b)
		decoded, positions := decodePercent([]byte(escaped))
		if len(decoded) != 1 || int(decoded[0]) != b || len(positions) != 2 || positions[0] != 0 || positions[1] != 3 {
			t.Fatalf("byte %d", b)
		}
	}
}

func TestPercentPositionMapStaysWithinOriginalSize(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"%41", "prefix%41suffix", "%41%42%43", "prefix%41%0"} {
		decoded, positions := decodePercent([]byte(input))
		// One decoded escape saves two bytes, enough for the end sentinel.
		// Reserving more than the original size is unnecessary and risks overflow.
		if cap(positions) > len(input) || len(positions) != len(decoded)+1 {
			t.Fatalf("position map for %q exceeds its original-size budget", input)
		}
	}
}

type originalPercentDetector struct{ t *testing.T }

func (d originalPercentDetector) Scan(data []byte) []Finding {
	d.t.Helper()
	if string(data) != "a%40example.com" {
		d.t.Fatal("custom detector input was decoded")
	}
	return []Finding{{Kind: "custom", Start: 1, End: 4, Confidence: .5}}
}

func TestEncodedBuiltinAndRawCustomOffsets(t *testing.T) {
	t.Parallel()
	text := "a%40example.com"
	got := NewScanner(WithKinds(KindEmail), WithDetector(originalPercentDetector{t: t})).ScanString(text)
	if len(got) != 2 || got[0].Kind != KindEmail || got[0].Start != 0 || got[0].End != len(text) || got[1].Start != 1 || got[1].End != 4 {
		t.Fatalf("mixed offsets: %+v", got)
	}
	if masked := Mask(text, got); masked != redactionMarker {
		t.Fatalf("escaped masking: %q", masked)
	}
}
