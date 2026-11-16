package detect_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

func TestETHDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detect.NewETH()

	tests := []struct {
		name        string
		input       string
		wantRaw     string
		wantLen     int
		wantMinConf float64
		wantEIP55   bool
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
			if f.DetectorName != detect.NameETH {
				t.Errorf("DetectorName = %q, want %q", f.DetectorName, detect.NameETH)
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

	d := detect.NewETH()

	tests := []struct {
		name  string
		input string
	}{
		//nolint:goconst // Each test states its fixture and expected result independently.
		{name: "empty input", input: ""},
		{name: "plain text", input: "hello world no ethereum here"},
		{name: "0x too short", input: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe"},
		{name: "0x too long", input: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed0"},
		{name: "non-hex chars", input: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BzZzz"},
		{name: "invalid EIP-55 checksum", input: "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{name: "preceded by letter", input: "x0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"},
		//nolint:goconst // Each test states its fixture and expected result independently.
		{name: "preceded by underscore", input: "_0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"},
		{name: "followed by hex char", input: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed0"},
		{name: "followed by letter", input: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaedx"},
		{name: "followed by underscore", input: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed_"},
		{name: "just 0x prefix", input: "0x"},
		{name: "hex string without 0x", input: "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{name: "log line no eth", input: "2024-01-15T10:30:00Z INFO server started on port 8080"},
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

	d := detect.NewETH()
	if d.Name() != detect.NameETH {
		t.Errorf("Name() = %q, want %q", d.Name(), detect.NameETH)
	}
}

func TestETHDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detect.NewETH()
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

	d := detect.NewETH()
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

	d := detect.NewETH()

	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{name: "preceded by space", input: " 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", wantLen: 1},
		{name: "preceded by colon", input: ":0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", wantLen: 1},
		{name: "preceded by newline", input: "\n0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", wantLen: 1},
		{name: "followed by space", input: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed ", wantLen: 1},
		{name: "followed by comma", input: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed,", wantLen: 1},
		{name: "followed by period", input: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed.", wantLen: 1},
		{name: "preceded by letter", input: "x0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", wantLen: 0},
		{name: "preceded by digit", input: "10x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", wantLen: 0},
		{name: "preceded by underscore", input: "_0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", wantLen: 0},
		{name: "followed by underscore", input: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed_", wantLen: 0},
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

	d := detect.NewETH()

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

func TestETHSpecificationVectors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/eip55.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []string
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, raw := range vectors {
		got := detect.NewETH().Scan([]byte(raw))
		want := 0.95
		if raw[2:] == strings.ToLower(raw[2:]) || raw[2:] == strings.ToUpper(raw[2:]) {
			want = 0.80
		}
		if len(got) != 1 || got[0].RawValue != raw || got[0].Confidence != want {
			t.Errorf("EIP-55 vector rejected or mis-scored: %s", raw)
		}
		if len(detect.NewETH().Scan([]byte(raw+"0"))) != 0 {
			t.Fatal("overlong ETH address accepted")
		}
		if want == 0.95 {
			for i := 2; i < len(raw); i++ {
				bad := []byte(raw)
				switch {
				case bad[i] >= 'a' && bad[i] <= 'f':
					bad[i] -= 32
				case bad[i] >= 'A' && bad[i] <= 'F':
					bad[i] += 32
				default:
					continue
				}
				if len(detect.NewETH().Scan(bad)) != 0 {
					t.Fatalf("one-letter EIP-55 mutation accepted: %s", bad)
				}
			}
		}
	}
}
