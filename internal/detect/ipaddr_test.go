package detect

import (
	"fmt"
	"strings"
	"testing"
)

func TestIPAddrDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewIPAddr()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "IPv4 address",
			input:      "from 192.168.1.1 to server",
			wantLen:    1,
			wantRaw:    "192.168.1.1",
			wantMinCon: 0.7,
		},
		{
			name:       "IPv4 loopback",
			input:      loopbackIPv4,
			wantLen:    0,
			wantRaw:    loopbackIPv4,
			wantMinCon: 0.7,
		},

		// False positives
		{
			name:    "version number",
			input:   "v1.2.3",
			wantLen: 0,
		},
		{
			name:    emptyInputCase,
			input:   "",
			wantLen: 0,
		},
		{
			name:    "octet out of range",
			input:   "999.999.999.999",
			wantLen: 0,
		},
		{
			name:    "digit prefix should not match",
			input:   "1192.168.1.1",
			wantLen: 0,
		},
		{
			name:    "digit suffix should not match",
			input:   "192.168.1.12345",
			wantLen: 0,
		},
		{
			name:    "underscore suffix should not match",
			input:   "192.168.1.1_label",
			wantLen: 0,
		},
		{
			name:    "hyphen suffix should not match",
			input:   "192.168.1.1-backup",
			wantLen: 0,
		},
		{
			name:    "letter suffix should not match",
			input:   "192.168.1.1a",
			wantLen: 0,
		},
		{
			name:    "underscore prefix should not match",
			input:   "_192.168.1.1",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assertDetectorScan(t, d, tt.input, tt.wantLen, tt.wantRaw, tt.wantMinCon)
		})
	}
}

func TestIPAddrDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewIPAddr()
	findings := d.Scan([]byte("192.168.1.1"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	_, address := parseIPSentence("192.168.1.1"[findings[0].Start:findings[0].End])
	version := 6
	if address.To4() != nil {
		version = 4
	}
	if version != 4 {
		t.Errorf("Version = %d, want 4", version)
	}
}

func TestIPAddrDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewIPAddr()
	if d.Name() != NameIPAddr {
		t.Errorf("Name() = %q, want %q", d.Name(), NameIPAddr)
	}
}

func TestIPAddrDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewIPAddr()
	hints := d.Hints()
	if len(hints) != 2 {
		t.Errorf("Hints() returned %d hints, want 2", len(hints))
	}
}

func TestIPAddrDetector_IPv6(t *testing.T) {
	t.Parallel()

	d := NewIPAddr()
	tests := []struct {
		name    string
		input   string
		wantRaw string
		wantLen int
	}{
		{
			name:    "full IPv6",
			input:   "addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 here",
			wantLen: 1,
			wantRaw: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
		{
			name:    "IPv6 loopback",
			input:   loopbackIPv6,
			wantLen: 0,
			wantRaw: loopbackIPv6,
		},
		{
			name:    "IPv6 shortened",
			input:   "fe80::1",
			wantLen: 1,
			wantRaw: "fe80::1",
		},
		{
			name:    "IPv6 preceded by alpha",
			input:   "xfe80::1",
			wantLen: 0,
		},
		{
			name:    "IPv6 preceded by underscore",
			input:   "_fe80::1",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen > 0 && tt.wantRaw != "" {
				if tt.input[findings[0].Start:findings[0].End] != tt.wantRaw {
					t.Errorf("matched text = %q, want %q", tt.input[findings[0].Start:findings[0].End], tt.wantRaw)
				}
				_, address := parseIPSentence(tt.input[findings[0].Start:findings[0].End])
				version := 6
				if address.To4() != nil {
					version = 4
				}
				if version != 6 {
					t.Errorf("Version = %d, want 6", version)
				}
			}
		})
	}
}

func TestIPAddrDetector_IPv4FollowedByDot(t *testing.T) {
	t.Parallel()

	d := NewIPAddr()
	findings := d.Scan([]byte("192.168.1.1."))
	if len(findings) != 1 || findings[0].End != len("192.168.1.1") {
		t.Errorf("got %v findings for IP followed by dot, want the address only", findings)
	}
}

func TestIPAddrDetector_MultipleIPs(t *testing.T) {
	t.Parallel()

	d := NewIPAddr()
	findings := d.Scan([]byte("from 10.0.0.1 to 10.0.0.2"))
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
}

func TestIPAddrDetector_DotPrefixed(t *testing.T) {
	t.Parallel()

	d := NewIPAddr()
	findings := d.Scan([]byte(".192.168.1.1"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for dot-prefixed IP, want 0", len(findings))
	}
}

func TestIPAddrDetector_IPv6TrailingBoundary(t *testing.T) {
	t.Parallel()

	d := NewIPAddr()
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{
			name:    "trailing non-hex letter should reject",
			input:   "2001:db8::1g",
			wantLen: 0,
		},
		{
			name:    "trailing letters xyz should reject",
			input:   "fe80::1xyz",
			wantLen: 0,
		},
		{
			name:    "space separated is standalone",
			input:   "addr 2001:db8::1 ok",
			wantLen: 1,
		},
		{
			name:    "end of string is standalone",
			input:   "addr fe80::1",
			wantLen: 1,
		},
		{
			name:    "trailing underscore should reject",
			input:   "2001:db8::1_tag",
			wantLen: 0,
		},
		{
			name:    "trailing hyphen should reject",
			input:   "fe80::1-eth0",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tt.wantLen, findings)
			}
		})
	}
}

func TestIPLocalAddressesAreNotPrivateEndpoints(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"0.0.0.0", "::", loopbackIPv4, "127.255.255.254", loopbackIPv6} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			if got := NewIPAddr().Scan([]byte("listener [" + address + "]")); len(got) != 0 {
				t.Fatal("host-independent address must not identify a private endpoint")
			}
		})
	}
	for _, address := range []string{"10.0.0.1", "126.255.255.255", "128.0.0.1", "192.0.2.1", "2001:db8::1"} {
		if got := NewIPAddr().Scan([]byte(address)); len(got) != 1 || got[0].Start != 0 || got[0].End != len(address) {
			t.Fatal("endpoint protection changed")
		}
	}
}

func TestIPVersionLabels(t *testing.T) {
	t.Parallel()
	for _, label := range []string{"version", "v", "ver", "build", "release", "VERSION"} {
		for _, sep := range []string{" ", "=", ": ", "\":\""} {
			input := label + sep + "10.2.3.4"
			if got := NewIPAddr().Scan([]byte(input)); len(got) != 0 {
				t.Errorf("version treated as IP: %s", input)
			}
		}
	}
}

func TestIPSentencePunctuationProperty(t *testing.T) {
	t.Parallel()
	detector := NewIPAddr()
	punctuation := []string{"...", ".:", ":."}
	for b := byte('!'); b <= '~'; b++ {
		if !strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", rune(b)) {
			punctuation = append(punctuation, string(b))
		}
	}
	for n := 1; n < 255; n += 13 {
		v4 := fmt.Sprintf("203.0.113.%d", n)
		for _, address := range []string{v4, fmt.Sprintf("2001:db8::%x", n), "2001:db8::", "::ffff:" + v4, "::" + v4, "64:ff9b::" + v4} {
			forms := []string{address, "[" + address + "]", "[" + address + "]:51234"}
			if address == v4 {
				forms = append(forms, address+":51234")
			}
			for _, form := range forms {
				for _, tail := range punctuation {
					input := "peer " + form + tail + " closed"
					got := detector.Scan([]byte(input))
					start := strings.Index(input, address)
					if len(got) != 1 || got[0].Start != start || got[0].End != start+len(address) || input[got[0].Start:got[0].End] != address {
						t.Fatalf("sentence punctuation changed the address boundary: %q: %+v", input, got)
					}
				}
			}
		}
	}
	for _, input := range []string{"203.0.113.9.8", "203.0.113.9_tail", "203.0.113.9-tail", "2001:db8::5_tail", "2001:db8::5-tail"} {
		if got := detector.Scan([]byte(input)); len(got) != 0 {
			t.Fatalf("larger token accepted: %q: %+v", input, got)
		}
	}
}

func TestIPRangeSpanProperty(t *testing.T) {
	t.Parallel()
	detector := NewIPAddr()
	for n := 1; n < 32; n++ {
		addresses := []string{fmt.Sprintf("198.51.100.%d", n), fmt.Sprintf("fd00::%x", n), fmt.Sprintf("::ffff:203.0.113.%d", n)}
		for _, left := range addresses {
			for _, right := range addresses {
				got := detector.Scan([]byte(left + "-" + right))
				if len(got) != 2 || got[0].Start != 0 || got[0].End != len(left) || got[1].Start != len(left)+1 || got[1].End != len(left)+1+len(right) {
					t.Fatalf("range endpoints lost: %+v", got)
				}
			}
		}
	}
}

func TestIPTrailingIdentifierEdges(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"203.0.113.9", "2001:db8::7"} {
		for _, suffix := range []string{"_", "-", "_a", "_0", "-a"} {
			t.Run(address+suffix, func(t *testing.T) {
				t.Parallel()
				want := 0
				if suffix == "_" || suffix == "-" {
					want = 1
				}
				assertDetectorScan(t, NewIPAddr(), address+suffix, want, address, 0)
			})
		}
	}
}
