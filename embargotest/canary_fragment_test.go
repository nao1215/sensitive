package embargotest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

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
