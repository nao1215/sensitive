package detect

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestBTCDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewBTC()

	tests := []struct {
		name        string
		input       string
		wantType    BTCAddressType
		wantRaw     string
		wantLen     int
		wantMinConf float64
	}{
		// P2PKH (prefix '1')
		{
			name:        "P2PKH genesis block address",
			input:       "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa please",
			wantLen:     1,
			wantType:    BTCAddressP2PKH,
			wantRaw:     sampleBase58,
			wantMinConf: 0.9,
		},
		{
			name:        "P2PKH at start of input",
			input:       sampleBase58,
			wantLen:     1,
			wantType:    BTCAddressP2PKH,
			wantRaw:     sampleBase58,
			wantMinConf: 0.9,
		},
		// P2SH (prefix '3')
		{
			name:        "P2SH address",
			input:       "addr: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
			wantLen:     1,
			wantType:    BTCAddressP2SH,
			wantRaw:     "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
			wantMinConf: 0.9,
		},
		// Bech32 SegWit v0 (prefix 'bc1q')
		{
			name:        "Bech32 P2WPKH (42 chars)",
			input:       "segwit: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			wantLen:     1,
			wantType:    BTCAddressBech32,
			wantRaw:     sampleBech32,
			wantMinConf: 0.9,
		},
		{
			name:        "Bech32 P2WPKH uppercase",
			input:       "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
			wantLen:     1,
			wantType:    BTCAddressBech32,
			wantRaw:     "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
			wantMinConf: 0.9,
		},
		// Bech32m Taproot v1 (prefix 'bc1p')
		{
			name:        "Bech32m P2TR (62 chars)",
			input:       "taproot: bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
			wantLen:     1,
			wantType:    BTCAddressBech32m,
			wantRaw:     "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
			wantMinConf: 0.9,
		},
		// Multiple addresses
		{
			name:        "multiple BTC addresses",
			input:       "from 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			wantLen:     2,
			wantType:    "", // don't check type for multi
			wantRaw:     "",
			wantMinConf: 0.9,
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
			if f.DetectorName != NameBTC {
				t.Errorf("DetectorName = %q, want %q", f.DetectorName, NameBTC)
			}
			if tt.wantRaw != "" && tt.input[f.Start:f.End] != tt.wantRaw {
				t.Errorf("matched text = %q, want %q", tt.input[f.Start:f.End], tt.wantRaw)
			}
			if f.Confidence < tt.wantMinConf {
				t.Errorf("Confidence = %.2f, want >= %.2f", f.Confidence, tt.wantMinConf)
			}
			if tt.wantType != "" {
				addressType := checkedBTCEncoding(t, tt.input[f.Start:f.End])
				if addressType != tt.wantType {
					t.Errorf("AddressType = %q, want %q", addressType, tt.wantType)
				}
			}
		})
	}
}

func TestBTCDetector_Scan_NoMatch(t *testing.T) {
	t.Parallel()

	d := NewBTC()

	tests := []struct {
		name  string
		input string
	}{
		{name: emptyInputCase, input: ""},
		{name: "plain text", input: "hello world no bitcoin here"},
		{name: "short string starting with 1", input: "1abc"},
		{name: "number starting with 3", input: "3.14159"},
		{name: "invalid base58 char O", input: "1OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO"},
		{name: "invalid base58 char I", input: "1IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII"},
		{name: "invalid base58 char l", input: "1lllllllllllllllllllllllllllllllll"},
		{name: "invalid base58 char 0", input: "10000000000000000000000000000000000"},
		{name: "too short legacy", input: "1A1zP1eP5QGefi2DM"},
		{name: "wrong checksum P2PKH", input: "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfxx"},
		{name: "bech32 mixed case in data part", input: "bc1qW508D6QEjxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{name: "bech32 uppercase HRP with lowercase data", input: "BC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{name: "bech32 lowercase HRP with uppercase data", input: "bc1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"},
		{name: "bech32 wrong length (50 chars)", input: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t412345"},
		{name: "bech32 wrong checksum", input: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"},
		{name: "part of identifier", input: "abc1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{name: "identifier suffix", input: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa_xyz"},
		{name: "bech32m wrong witness version", input: "bc1qw508d6qejxtdg4y5r3zarvaryd97k2cct85pqh48"},
		{name: "plain digits starting with 1", input: "12345678901234567890123456"},
		{name: "log line with 1", input: "2024-01-15T10:30:00Z INFO server started on port 8080"},
		{name: "version string with 3", input: "v3.2.1 released"},
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

func TestBTCDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewBTC()
	if d.Name() != NameBTC {
		t.Errorf("Name() = %q, want %q", d.Name(), NameBTC)
	}
}

func TestBTCDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewBTC()
	if d.Hints() != nil {
		t.Error("Hints() should return nil for BTC detector")
	}
}

func TestBTCDetector_Scan_BytePositions(t *testing.T) {
	t.Parallel()

	d := NewBTC()
	input := "btc: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa end"
	findings := d.Scan([]byte(input))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	expectedStart := 5
	expectedEnd := 5 + 34 // sampleBase58 is 34 chars
	if f.Start != expectedStart {
		t.Errorf("Start = %d, want %d", f.Start, expectedStart)
	}
	if f.End != expectedEnd {
		t.Errorf("End = %d, want %d", f.End, expectedEnd)
	}
}

func TestBTCDetector_Scan_BoundaryChecks(t *testing.T) {
	t.Parallel()

	d := NewBTC()

	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{name: "preceded by space", input: " 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 1},
		{name: "preceded by colon", input: ":1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 1},
		{name: "preceded by newline", input: "\n1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 1},
		{name: "followed by space", input: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa ", wantLen: 1},
		{name: "followed by comma", input: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa,", wantLen: 1},
		{name: "followed by period", input: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.", wantLen: 1},
		{name: "btc preceded by letter", input: "x1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 0},
		{name: "btc preceded by underscore", input: "_1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 0},
		{name: "btc followed by underscore", input: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa_", wantLen: 0},
		{name: "preceded by digit", input: "91A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 0},
		{name: "preceded by zero (non-base58)", input: "01A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 0},
		{name: "preceded by I (non-base58)", input: "I1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 0},
		{name: "preceded by O (non-base58)", input: "O1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 0},
		{name: "preceded by l (non-base58)", input: "l1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wantLen: 0},
		{name: "bech32 preceded by space", input: " bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", wantLen: 1},
		{name: "bech32 preceded by letter", input: "xbc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", wantLen: 0},
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

func TestBase58Decode(t *testing.T) {
	t.Parallel()

	// Test that a known valid address decodes to 25 bytes.
	// sampleBase58 - genesis block coinbase address.
	d := NewBTC()
	findings := d.Scan([]byte(sampleBase58))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for genesis address, got %d", len(findings))
	}

	addressType := checkedBTCEncoding(t, sampleBase58[findings[0].Start:findings[0].End])
	if addressType != BTCAddressP2PKH {
		t.Errorf("AddressType = %q, want %q", addressType, BTCAddressP2PKH)
	}
}

func TestBech32Checksum(t *testing.T) {
	t.Parallel()

	d := NewBTC()

	// BIP-173 test vector: valid bech32 P2WPKH address.
	findings := d.Scan([]byte(sampleBech32))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for BIP-173 test vector, got %d", len(findings))
	}

	addressType := checkedBTCEncoding(t, sampleBech32[findings[0].Start:findings[0].End])
	if addressType != BTCAddressBech32 {
		t.Errorf("AddressType = %q, want %q", addressType, BTCAddressBech32)
	}
}

func TestBech32mChecksum(t *testing.T) {
	t.Parallel()

	d := NewBTC()

	// BIP-350 test vector: valid bech32m P2TR address.
	findings := d.Scan([]byte("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for BIP-350 test vector, got %d", len(findings))
	}

	addressType := checkedBTCEncoding(t, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"[findings[0].Start:findings[0].End])
	if addressType != BTCAddressBech32m {
		t.Errorf("AddressType = %q, want %q", addressType, BTCAddressBech32m)
	}
}

func TestBTCSpecificationVectors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/bitcoin.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Source string `json:"source"`
		Raw    string `json:"raw"`
		Valid  bool   `json:"valid"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		got := NewBTC().Scan([]byte(v.Raw))
		if (len(got) == 1) != v.Valid {
			t.Errorf("%s %s: valid=%v got %v", v.Source, v.Raw, v.Valid, got)
		}
	}
}

func TestBtcRejectedBoundaries(t *testing.T) {
	t.Parallel()
	if _, _, ok := NewBTC().scanLegacy([]byte("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"), 0); ok {
		t.Fatal("unsupported network accepted")
	}
}

// Check the published address encodings through their checksum primitives.
func checkedBTCEncoding(t *testing.T, address string) BTCAddressType {
	t.Helper()
	if strings.HasPrefix(strings.ToLower(address), "bc1") {
		decoded, ok := decodeBech32Chars(strings.ToLower(address)[3:])
		if !ok {
			t.Fatal("invalid Bech32 alphabet")
		}
		variant, ok := bech32VerifyChecksum("bc", decoded)
		if !ok {
			t.Fatal("invalid Bech32 checksum")
		}
		if variant == bech32ChecksumConst {
			return BTCAddressBech32
		}
		return BTCAddressBech32m
	}
	decoded, ok := base58Decode(address)
	if !ok || len(decoded) != 25 || !validateBase58Checksum(decoded) {
		t.Fatal("invalid Base58Check address")
	}
	if decoded[0] == 0 {
		return BTCAddressP2PKH
	}
	return BTCAddressP2SH
}

// BTCAddressType names expected encodings in the published checksum vectors.
type BTCAddressType string

const (
	// BTCAddressP2PKH identifies Pay-to-Public-Key-Hash addresses (prefix '1').
	BTCAddressP2PKH BTCAddressType = "p2pkh"
	// BTCAddressP2SH identifies Pay-to-Script-Hash addresses (prefix '3').
	BTCAddressP2SH BTCAddressType = "p2sh"
	// BTCAddressBech32 identifies SegWit v0 addresses (prefix 'bc1q').
	BTCAddressBech32 BTCAddressType = "bech32"
	// BTCAddressBech32m identifies witness versions 1–16 using Bech32m.
	BTCAddressBech32m BTCAddressType = "bech32m"
)
