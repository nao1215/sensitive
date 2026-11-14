package detector_test

import (
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"math/rand/v2"
	"os"
	"slices"
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestBTCDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewBTC()

	tests := []struct {
		name        string
		input       string
		wantLen     int
		wantType    detector.BTCAddressType
		wantRaw     string
		wantMinConf float64
	}{
		// P2PKH (prefix '1')
		{
			name:        "P2PKH genesis block address",
			input:       "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa please",
			wantLen:     1,
			wantType:    detector.BTCAddressP2PKH,
			wantRaw:     "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			wantMinConf: 0.9,
		},
		{
			name:        "P2PKH at start of input",
			input:       "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			wantLen:     1,
			wantType:    detector.BTCAddressP2PKH,
			wantRaw:     "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			wantMinConf: 0.9,
		},
		// P2SH (prefix '3')
		{
			name:        "P2SH address",
			input:       "addr: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
			wantLen:     1,
			wantType:    detector.BTCAddressP2SH,
			wantRaw:     "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
			wantMinConf: 0.9,
		},
		// Bech32 SegWit v0 (prefix 'bc1q')
		{
			name:        "Bech32 P2WPKH (42 chars)",
			input:       "segwit: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			wantLen:     1,
			wantType:    detector.BTCAddressBech32,
			wantRaw:     "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			wantMinConf: 0.9,
		},
		{
			name:        "Bech32 P2WPKH uppercase",
			input:       "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
			wantLen:     1,
			wantType:    detector.BTCAddressBech32,
			wantRaw:     "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
			wantMinConf: 0.9,
		},
		// Bech32m Taproot v1 (prefix 'bc1p')
		{
			name:        "Bech32m P2TR (62 chars)",
			input:       "taproot: bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
			wantLen:     1,
			wantType:    detector.BTCAddressBech32m,
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
			if f.DetectorName != detector.NameBTC {
				t.Errorf("DetectorName = %q, want %q", f.DetectorName, detector.NameBTC)
			}
			if tt.wantRaw != "" && f.RawValue != tt.wantRaw {
				t.Errorf("RawValue = %q, want %q", f.RawValue, tt.wantRaw)
			}
			if f.Confidence < tt.wantMinConf {
				t.Errorf("Confidence = %.2f, want >= %.2f", f.Confidence, tt.wantMinConf)
			}
			if tt.wantType != "" {
				detail, ok := f.BTCDetail()
				if !ok {
					t.Fatal("BTCDetail() returned false")
				}
				if detail.AddressType != tt.wantType {
					t.Errorf("AddressType = %q, want %q", detail.AddressType, tt.wantType)
				}
			}
		})
	}
}

func TestBTCDetector_Scan_NoMatch(t *testing.T) {
	t.Parallel()

	d := detector.NewBTC()

	tests := []struct {
		name  string
		input string
	}{
		{"empty input", ""},
		{"plain text", "hello world no bitcoin here"},
		{"short string starting with 1", "1abc"},
		{"number starting with 3", "3.14159"},
		{"invalid base58 char O", "1OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO"},
		{"invalid base58 char I", "1IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII"},
		{"invalid base58 char l", "1lllllllllllllllllllllllllllllllll"},
		{"invalid base58 char 0", "10000000000000000000000000000000000"},
		{"too short legacy", "1A1zP1eP5QGefi2DM"},
		{"wrong checksum P2PKH", "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfxx"},
		{"bech32 mixed case in data part", "bc1qW508D6QEjxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{"bech32 uppercase HRP with lowercase data", "BC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{"bech32 lowercase HRP with uppercase data", "bc1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"},
		{"bech32 wrong length (50 chars)", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t412345"},
		{"bech32 wrong checksum", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"},
		{"part of identifier", "abc1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{"identifier suffix", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa_xyz"},
		{"bech32m wrong witness version", "bc1qw508d6qejxtdg4y5r3zarvaryd97k2cct85pqh48"},
		{"plain digits starting with 1", "12345678901234567890123456"},
		{"log line with 1", "2024-01-15T10:30:00Z INFO server started on port 8080"},
		{"version string with 3", "v3.2.1 released"},
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

	d := detector.NewBTC()
	if d.Name() != detector.NameBTC {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameBTC)
	}
}

func TestBTCDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewBTC()
	if d.Hints() != nil {
		t.Error("Hints() should return nil for BTC detector")
	}
}

func TestBTCDetector_Scan_BytePositions(t *testing.T) {
	t.Parallel()

	d := detector.NewBTC()
	input := "btc: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa end"
	findings := d.Scan([]byte(input))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	expectedStart := 5
	expectedEnd := 5 + 34 // "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" is 34 chars
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

func TestBTCDetector_Scan_BoundaryChecks(t *testing.T) {
	t.Parallel()

	d := detector.NewBTC()

	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"preceded by space", " 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1},
		{"preceded by colon", ":1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1},
		{"preceded by newline", "\n1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1},
		{"followed by space", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa ", 1},
		{"followed by comma", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa,", 1},
		{"followed by period", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.", 1},
		{"preceded by letter", "x1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0},
		{"preceded by underscore", "_1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0},
		{"followed by underscore", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa_", 0},
		{"preceded by digit", "91A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0},
		{"preceded by zero (non-base58)", "01A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0},
		{"preceded by I (non-base58)", "I1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0},
		{"preceded by O (non-base58)", "O1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0},
		{"preceded by l (non-base58)", "l1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0},
		{"bech32 preceded by space", " bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 1},
		{"bech32 preceded by letter", "xbc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 0},
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
	// "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" - genesis block coinbase address.
	d := detector.NewBTC()
	findings := d.Scan([]byte("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for genesis address, got %d", len(findings))
	}

	detail, ok := findings[0].BTCDetail()
	if !ok {
		t.Fatal("BTCDetail() returned false")
	}
	if detail.AddressType != detector.BTCAddressP2PKH {
		t.Errorf("AddressType = %q, want %q", detail.AddressType, detector.BTCAddressP2PKH)
	}
}

func TestBech32Checksum(t *testing.T) {
	t.Parallel()

	d := detector.NewBTC()

	// BIP-173 test vector: valid bech32 P2WPKH address.
	findings := d.Scan([]byte("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for BIP-173 test vector, got %d", len(findings))
	}

	detail, ok := findings[0].BTCDetail()
	if !ok {
		t.Fatal("BTCDetail() returned false")
	}
	if detail.AddressType != detector.BTCAddressBech32 {
		t.Errorf("AddressType = %q, want %q", detail.AddressType, detector.BTCAddressBech32)
	}
}

func TestBech32mChecksum(t *testing.T) {
	t.Parallel()

	d := detector.NewBTC()

	// BIP-350 test vector: valid bech32m P2TR address.
	findings := d.Scan([]byte("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for BIP-350 test vector, got %d", len(findings))
	}

	detail, ok := findings[0].BTCDetail()
	if !ok {
		t.Fatal("BTCDetail() returned false")
	}
	if detail.AddressType != detector.BTCAddressBech32m {
		t.Errorf("AddressType = %q, want %q", detail.AddressType, detector.BTCAddressBech32m)
	}
}

func TestBTCSpecificationVectors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/bitcoin.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Source string
		Raw    string
		Valid  bool
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		got := detector.NewBTC().Scan([]byte(v.Raw))
		if (len(got) == 1) != v.Valid {
			t.Errorf("%s %s: valid=%v got %v", v.Source, v.Raw, v.Valid, got)
		}
	}
}

// encodeWitness independently implements BIP-173/BIP-350's encoder; the
// production detector only decodes and validates addresses.
func encodeWitness(version byte, program []byte) string {
	const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	values := []byte{version}
	accumulator, bits := uint32(0), uint(0)
	for _, b := range program {
		accumulator = accumulator<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			values = append(values, byte(accumulator>>bits&31))
		}
	}
	if bits > 0 {
		values = append(values, byte(accumulator<<(5-bits)&31))
	}
	expanded := append([]byte{3, 3, 0, 2, 3}, values...)
	expanded = append(expanded, 0, 0, 0, 0, 0, 0)
	checksum := uint32(1)
	generators := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range expanded {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range generators {
			if top>>i&1 != 0 {
				checksum ^= g
			}
		}
	}
	if version == 0 {
		checksum ^= 1
	} else {
		checksum ^= 0x2bc830a3
	}
	result := []byte("bc1")
	for _, v := range values {
		result = append(result, alphabet[v])
	}
	for i := 5; i >= 0; i-- {
		result = append(result, alphabet[checksum>>uint(5*i)&31])
	}
	return string(result)
}

func TestBTCGeneratedAddresses(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(173, 350))
	for range 100 {
		payload := make([]byte, 20)
		for i := range payload {
			payload[i] = byte(rng.Uint32() & 255)
		}
		for _, version := range []byte{0, 5} {
			binary := append([]byte{version}, payload...)
			first := sha256.Sum256(binary)
			second := sha256.Sum256(first[:])
			binary = append(binary, second[:4]...)
			n := new(big.Int).SetBytes(binary)
			base := big.NewInt(58)
			rem := new(big.Int)
			var reversed []byte
			for n.Sign() > 0 {
				n.QuoRem(n, base, rem)
				reversed = append(reversed, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[rem.Int64()])
			}
			for _, b := range binary {
				if b != 0 {
					break
				}
				reversed = append(reversed, '1')
			}
			slices.Reverse(reversed)
			assertBTCGenerated(t, string(reversed))
		}
		assertBTCGenerated(t, encodeWitness(0, payload))
		program := make([]byte, 32)
		copy(program, payload)
		copy(program[20:], payload[:12])
		assertBTCGenerated(t, encodeWitness(0, program))
		assertBTCGenerated(t, encodeWitness(1, program))
	}
}

func assertBTCGenerated(t *testing.T, raw string) {
	t.Helper()
	got := detector.NewBTC().Scan([]byte(raw))
	if len(got) != 1 || got[0].RawValue != raw || got[0].Confidence != 0.95 {
		t.Fatalf("generated Bitcoin address rejected: %s", raw)
	}
	// Change one checksum character; every substitution must invalidate it.
	bad := []byte(raw)
	if bad[len(bad)-1] == 'q' {
		bad[len(bad)-1] = 'p'
	} else {
		bad[len(bad)-1] = 'q'
	}
	if len(detector.NewBTC().Scan(bad)) != 0 {
		t.Fatalf("checksum mutation accepted: %s", bad)
	}
}
