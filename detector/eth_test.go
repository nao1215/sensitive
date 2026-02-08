package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestETHDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewETH()

	tests := []struct {
		name        string
		input       string
		wantLen     int
		wantRaw     string
		wantEIP55   bool
		wantMinConf float64
	}{
		// EIP-55 checksummed addresses (official test vectors).
		{
			name:        "EIP-55 test vector 1",
			input:       "addr: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
			wantLen:     1,
			wantRaw:     "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
			wantEIP55:   true,
			wantMinConf: 0.9,
		},
		{
			name:        "EIP-55 test vector 2",
			input:       "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
			wantLen:     1,
			wantRaw:     "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
			wantEIP55:   true,
			wantMinConf: 0.9,
		},
		{
			name:        "EIP-55 test vector 3",
			input:       "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
			wantLen:     1,
			wantRaw:     "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
			wantEIP55:   true,
			wantMinConf: 0.9,
		},
		{
			name:        "EIP-55 test vector 4",
			input:       "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
			wantLen:     1,
			wantRaw:     "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
			wantEIP55:   true,
			wantMinConf: 0.9,
		},
		// All-lowercase address (valid, no checksum).
		{
			name:        "all-lowercase ETH address",
			input:       "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
			wantLen:     1,
			wantRaw:     "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
			wantEIP55:   false,
			wantMinConf: 0.7,
		},
		// All-uppercase address (valid, no checksum).
		{
			name:        "all-uppercase ETH address",
			input:       "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED",
			wantLen:     1,
			wantRaw:     "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED",
			wantEIP55:   false,
			wantMinConf: 0.7,
		},
		// Digits-only address (no letters, uniform case).
		{
			name:        "digits-only hex (0x prefix + 40 digits)",
			input:       "0x0000000000000000000000000000000000000000",
			wantLen:     1,
			wantRaw:     "0x0000000000000000000000000000000000000000",
			wantEIP55:   false,
			wantMinConf: 0.7,
		},
		// Address in context.
		{
			name:        "ETH address in log line",
			input:       "transfer from 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed to 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
			wantLen:     2,
			wantRaw:     "",
			wantEIP55:   true,
			wantMinConf: 0.9,
		},
		// 0X prefix (uppercase X).
		{
			name:        "0X prefix uppercase",
			input:       "0X5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
			wantLen:     1,
			wantRaw:     "0X5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
			wantEIP55:   false,
			wantMinConf: 0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantLen)
			}
			if tt.wantLen == 0 {
				return
			}
			f := findings[0]
			if f.DetectorName != detector.NameETH {
				t.Errorf("DetectorName = %q, want %q", f.DetectorName, detector.NameETH)
			}
			if tt.wantRaw != "" && f.RawValue != tt.wantRaw {
				t.Errorf("RawValue = %q, want %q", f.RawValue, tt.wantRaw)
			}
			if f.Confidence < tt.wantMinConf {
				t.Errorf("Confidence = %.2f, want >= %.2f", f.Confidence, tt.wantMinConf)
			}
			detail, ok := f.ETHDetail()
			if !ok {
				t.Fatal("ETHDetail() returned false")
			}
			if detail.EIP55 != tt.wantEIP55 {
				t.Errorf("EIP55 = %v, want %v", detail.EIP55, tt.wantEIP55)
			}
		})
	}
}

func TestETHDetector_Scan_NoMatch(t *testing.T) {
	t.Parallel()

	d := detector.NewETH()

	tests := []struct {
		name  string
		input string
	}{
		{"empty input", ""},
		{"plain text", "hello world no ethereum here"},
		{"0x too short", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe"},
		{"0x too long", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed0"},
		{"non-hex chars", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BzZzz"},
		{"invalid EIP-55 checksum", "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{"preceded by letter", "x0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"},
		{"preceded by underscore", "_0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"},
		{"followed by hex char", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed0"},
		{"followed by letter", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaedx"},
		{"followed by underscore", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed_"},
		{"just 0x prefix", "0x"},
		{"hex string without 0x", "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{"log line no eth", "2024-01-15T10:30:00Z INFO server started on port 8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0; first: %+v", len(findings), findings[0])
			}
		})
	}
}

func TestETHDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewETH()
	if d.Name() != detector.NameETH {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameETH)
	}
}

func TestETHDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewETH()
	hints := d.Hints()
	if len(hints) != 2 {
		t.Fatalf("Hints() returned %d hints, want 2", len(hints))
	}
	if string(hints[0]) != "0x" {
		t.Errorf("Hints()[0] = %q, want %q", hints[0], "0x")
	}
	if string(hints[1]) != "0X" {
		t.Errorf("Hints()[1] = %q, want %q", hints[1], "0X")
	}
}

func TestETHDetector_Scan_BytePositions(t *testing.T) {
	t.Parallel()

	d := detector.NewETH()
	input := "eth: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed end"
	findings := d.Scan([]byte(input))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	expectedStart := 5
	expectedEnd := 5 + 42
	if f.Start != expectedStart {
		t.Errorf("Start = %d, want %d", f.Start, expectedStart)
	}
	if f.End != expectedEnd {
		t.Errorf("End = %d, want %d", f.End, expectedEnd)
	}
	if input[f.Start:f.End] != f.RawValue {
		t.Errorf("input[%d:%d] = %q, want %q", f.Start, f.End, input[f.Start:f.End], f.RawValue)
	}
}

func TestETHDetector_Scan_BoundaryChecks(t *testing.T) {
	t.Parallel()

	d := detector.NewETH()

	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"preceded by space", " 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", 1},
		{"preceded by colon", ":0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", 1},
		{"preceded by newline", "\n0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", 1},
		{"followed by space", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed ", 1},
		{"followed by comma", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed,", 1},
		{"followed by period", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed.", 1},
		{"preceded by letter", "x0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", 0},
		{"preceded by digit", "10x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", 0},
		{"preceded by underscore", "_0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", 0},
		{"followed by underscore", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed_", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantLen)
			}
		})
	}
}

func TestETHDetector_EIP55Validation(t *testing.T) {
	t.Parallel()

	d := detector.NewETH()

	// Test that mixed-case addresses with wrong checksums are rejected.
	// Take a valid EIP-55 address and change one character's case.
	invalidEIP55 := "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" // 'a' at pos 3 changed to 'A'
	findings := d.Scan([]byte(invalidEIP55))
	if len(findings) != 0 {
		t.Errorf("invalid EIP-55 address should not match, got %d findings", len(findings))
	}

	// Valid EIP-55 address should match.
	validEIP55 := "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	findings = d.Scan([]byte(validEIP55))
	if len(findings) != 1 {
		t.Fatalf("valid EIP-55 address should match, got %d findings", len(findings))
	}
	if findings[0].Confidence < 0.9 {
		t.Errorf("Confidence = %.2f, want >= 0.9", findings[0].Confidence)
	}
}
