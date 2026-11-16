package embargotest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestCanaryRepresentations(t *testing.T) {
	t.Parallel()
	raw := []byte("fake-\"<&\nsecret-0123456789")
	//nolint:errchkjson // Keep marshal errors explicit under errcheck if serialized types evolve.
	j, err := json.Marshal(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	q := strconv.QuoteToASCII(string(raw))
	forms := make([]string, 0, 11)
	forms = append(forms, string(raw), hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw)), string(j[1:len(j)-1]), q[1:len(q)-1], fmt.Sprintf("%v", raw), new(big.Int).SetBytes(raw).String())
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		forms = append(forms, encoding.EncodeToString(raw))
	}
	for _, form := range forms {
		if !containsCanary([]byte("prefix "+form+" suffix"), representations(raw)) {
			t.Fatal("canary representation missed")
		}
	}
	if containsCanary(bytes.Repeat([]byte("x"), 200), representations(raw)) {
		t.Fatal("unrelated output detected")
	}
}

func TestCanaryFragmentsIndependentOfDetectors(t *testing.T) {
	t.Parallel()
	const canary = "distinctive-fixture-ABCDEFGH-123456789"
	digest := sha256.Sum256([]byte(canary))
	for _, tc := range []struct {
		name     string
		data     string
		detected bool
	}{
		{"minimum prefix", canary[:16], true},
		{"minimum interior", canary[3:19], true},
		{"minimum suffix", canary[len(canary)-16:], true},
		{"split records", canary[:18] + "\n" + canary[18:], true},
		{"one byte shorter", canary[:15], false},
		{"last four", canary[len(canary)-4:], false},
		{"hash", hex.EncodeToString(digest[:]), false},
		{"unrelated diagnostic", "request_id=REQ-7 order_id=ORD-9 completed=16", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			options := []Option{WithCanary([]byte(canary)), WithCanaryFragments(16), WithScanner(embargo.NewScanner(embargo.WithKinds()))}
			p := &probeTB{TB: t}
			r := New(p, options...)
			// Fragment boundaries can themselves cross separate writes.
			write(t, r, "out", []byte(tc.data[:3]))
			write(t, r, "out", []byte(tc.data[3:]))
			r.Expect("out", func(data []byte) bool { return bytes.Equal(data, []byte(tc.data)) })
			if r.Check() == tc.detected {
				t.Fatal("wrong fragment verdict")
			}
			p.finish()
			leaks, failed := guardLeaks([]byte(tc.data), guardPolicy(options))
			if failed || (len(leaks) > 0) != tc.detected {
				t.Fatal("Guard disagrees with recorder")
			}
			for _, message := range p.messages {
				if strings.Contains(message, canary[:16]) {
					t.Fatal("diagnostic echoed fragment")
				}
			}
		})
	}
}

func TestCanaryFragmentBoundsAndOrder(t *testing.T) {
	t.Parallel()
	const canary = "unique-public-fixture-ABCD"
	for _, minimum := range []int{-1, 0, 15, len(canary) + 1, 1025} {
		p := &probeTB{TB: t}
		r := New(p, WithCanaryFragments(minimum), WithCanary([]byte(canary)))
		write(t, r, "out", []byte("complete"))
		r.Expect("out", func([]byte) bool { return true })
		if r.Check() || !guardPolicy([]Option{WithCanaryFragments(minimum), WithCanary([]byte(canary))}).failed {
			t.Fatal("invalid minimum accepted")
		}
		p.finish()
	}
	for _, options := range [][]Option{
		{WithCanaryFragments(len(canary)), WithCanary([]byte(canary))},
		{WithCanary([]byte(canary)), WithCanaryFragments(len(canary))},
	} {
		policy := guardPolicy(options)
		if policy.failed || !containsCanary([]byte(canary), policy.needles) || containsCanary([]byte(canary[:len(canary)-1]), policy.needles) {
			t.Fatal("equal-length boundary or option order failed")
		}
	}
}

func TestCanaryFragmentRepeatedWindowsAreBounded(t *testing.T) {
	t.Parallel()
	policy := guardPolicy([]Option{WithCanary([]byte(strings.Repeat("x", 1024))), WithCanaryFragments(16)})
	count := 0
	for _, needle := range policy.needles {
		if string(needle) == strings.Repeat("x", 16) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("repeated fragment retained %d times", count)
	}
}

// Independent encoders exercise representations that share no raw or Go-quoted
// substring, so removing the no-HTML JSON representation must be observable.
func TestCanaryJSONEscapingAndEmptyNeedles(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"prefix-\x01<&\n-suffix", "prefix-\u2028<&\t-suffix", "prefix-\x02é\"-suffix"} {
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(raw); err != nil {
			t.Fatal(err)
		}
		if !containsCanary(encoded.Bytes(), representations([]byte(raw))) {
			t.Fatal("unescaped JSON representation missed")
		}
	}
	if containsCanary([]byte("complete"), [][]byte{nil, {}}) {
		t.Fatal("empty needle matched unrelated output")
	}
	const maximum = 1024
	policy := guardPolicy([]Option{WithCanaryFragments(maximum), WithCanary(bytes.Repeat([]byte("z"), maximum))})
	if policy.failed || !containsCanary(policy.canary, policy.needles) || containsCanary(policy.canary[:maximum-1], policy.needles) {
		t.Fatal("maximum fragment length was not accepted exactly")
	}
}

func TestCanaryBase64AlignmentProperty(t *testing.T) {
	t.Parallel()
	for n := 16; n <= 40; n++ {
		canary := append([]byte("opaque-canary-"), bytes.Repeat([]byte{0xfb, 0xff, 0xef}, n)...)
		needles := representations(canary)
		for prefix := range 6 {
			for suffix := range 6 {
				data := append(bytes.Repeat([]byte("x"), prefix), canary...)
				data = append(data, bytes.Repeat([]byte("z"), suffix)...)
				for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
					if !containsCanary([]byte(encoding.EncodeToString(data)), needles) {
						t.Errorf("missed alignment %d/%d at length %d", prefix, suffix, n)
					}
				}
			}
		}
	}
}

func TestCanaryExplicitDecodingBoundaries(t *testing.T) {
	t.Parallel()
	canary := []byte("opaque-canary-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	encoded := base64.StdEncoding.EncodeToString(canary)
	var wrapped, escaped strings.Builder
	for i, b := range []byte(encoded) {
		if err := wrapped.WriteByte(b); err != nil {
			t.Fatal(err)
		}
		if i%12 == 11 {
			if _, err := wrapped.WriteString("\r\n"); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, b := range canary {
		if _, err := fmt.Fprintf(&escaped, `\u%04x`, b); err != nil {
			t.Fatal(err)
		}
	}
	needles := representations(canary)
	for _, text := range []string{wrapped.String(), escaped.String()} {
		if containsCanary([]byte(text), needles) {
			t.Fatal("unsupported encoding contract changed")
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(wrapped.String())
	if err != nil {
		t.Fatal(err)
	}
	if !containsCanary(decoded, needles) {
		t.Fatal("decoded MIME canary missed")
	}
	var text string
	if err := json.Unmarshal([]byte(`"`+escaped.String()+`"`), &text); err != nil {
		t.Fatal(err)
	}
	if !containsCanary([]byte(text), needles) {
		t.Fatal("decoded Unicode canary missed")
	}
}
