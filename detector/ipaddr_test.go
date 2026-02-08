package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestIPAddrDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewIPAddr()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
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
			input:      "127.0.0.1",
			wantLen:    1,
			wantRaw:    "127.0.0.1",
			wantMinCon: 0.7,
		},

		// False positives
		{
			name:    "version number",
			input:   "v1.2.3",
			wantLen: 0,
		},
		{
			name:    "empty input",
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

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen > 0 && tt.wantRaw != "" {
				if findings[0].RawValue != tt.wantRaw {
					t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
				}
			}
			if tt.wantLen > 0 && tt.wantMinCon > 0 {
				if findings[0].Confidence < tt.wantMinCon {
					t.Errorf("Confidence = %f, want >= %f", findings[0].Confidence, tt.wantMinCon)
				}
			}
		})
	}
}

func TestIPAddrDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewIPAddr()
	findings := d.Scan([]byte("192.168.1.1"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].IPAddrDetail()
	if !ok {
		t.Fatal("IPAddrDetail() returned false")
	}
	if detail.Version != 4 {
		t.Errorf("Version = %d, want 4", detail.Version)
	}
}

func TestIPAddrDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewIPAddr()
	if d.Name() != detector.NameIPAddr {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameIPAddr)
	}
}

func TestIPAddrDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewIPAddr()
	hints := d.Hints()
	if len(hints) != 2 {
		t.Errorf("Hints() returned %d hints, want 2", len(hints))
	}
}

func TestIPAddrDetector_IPv6(t *testing.T) {
	t.Parallel()

	d := detector.NewIPAddr()
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantRaw string
	}{
		{
			name:    "full IPv6",
			input:   "addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 here",
			wantLen: 1,
			wantRaw: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
		{
			name:    "IPv6 loopback",
			input:   "::1",
			wantLen: 1,
			wantRaw: "::1",
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
				if findings[0].RawValue != tt.wantRaw {
					t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
				}
				detail, ok := findings[0].IPAddrDetail()
				if !ok {
					t.Fatal("IPAddrDetail() returned false")
				}
				if detail.Version != 6 {
					t.Errorf("Version = %d, want 6", detail.Version)
				}
			}
		})
	}
}

func TestIPAddrDetector_IPv4FollowedByDot(t *testing.T) {
	t.Parallel()

	d := detector.NewIPAddr()
	findings := d.Scan([]byte("192.168.1.1."))
	if len(findings) != 0 {
		t.Errorf("got %d findings for IP followed by dot, want 0", len(findings))
	}
}

func TestIPAddrDetector_MultipleIPs(t *testing.T) {
	t.Parallel()

	d := detector.NewIPAddr()
	findings := d.Scan([]byte("from 10.0.0.1 to 10.0.0.2"))
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
}

func TestIPAddrDetector_DotPrefixed(t *testing.T) {
	t.Parallel()

	d := detector.NewIPAddr()
	findings := d.Scan([]byte(".192.168.1.1"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for dot-prefixed IP, want 0", len(findings))
	}
}

func TestIPAddrDetector_IPv6TrailingBoundary(t *testing.T) {
	t.Parallel()

	d := detector.NewIPAddr()
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
