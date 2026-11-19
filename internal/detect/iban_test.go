package detect

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/ascii"
)

func TestIBANDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "German IBAN",
			input:      "IBAN: DE89370400440532013000",
			wantLen:    1,
			wantRaw:    "DE89370400440532013000",
			wantMinCon: 0.9,
		},
		{
			name:       "British IBAN",
			input:      "account GB29NWBK60161331926819",
			wantLen:    1,
			wantRaw:    "GB29NWBK60161331926819",
			wantMinCon: 0.9,
		},
		{
			name:       "IBAN with spaces",
			input:      "DE89 3704 0044 0532 0130 00",
			wantLen:    1,
			wantRaw:    "DE89 3704 0044 0532 0130 00",
			wantMinCon: 0.9,
		},

		// False positives
		{
			name:    "random uppercase letters + digits",
			input:   "XX1234567890",
			wantLen: 0,
		},
		{
			name:    emptyInputCase,
			input:   "",
			wantLen: 0,
		},
		{
			name:    "invalid check digits",
			input:   "DE00370400440532013000",
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

func TestIBANDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	findings := d.Scan([]byte("DE89370400440532013000"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	matched := "DE89370400440532013000"[findings[0].Start:findings[0].End]
	if strings.ToUpper(matched[:2]) != "DE" {
		t.Errorf("CountryCode = %q, want %q", strings.ToUpper(matched[:2]), "DE")
	}
}

func TestIBANDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	if d.Name() != NameIBAN {
		t.Errorf("Name() = %q, want %q", d.Name(), NameIBAN)
	}
}

func TestIBANDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	hints := d.Hints()
	// Hints returns nil so the Scanner always runs IBAN detection.
	// 2-byte country codes match normal text too frequently for effective
	// pre-filtering.
	if hints != nil {
		t.Errorf("Hints() = %v, want nil", hints)
	}
}

func TestIBANDetector_PrecededByAlpha(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	// IBAN preceded by alpha should not match.
	findings := d.Scan([]byte("xDE89370400440532013000"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for alpha-preceded IBAN, want 0", len(findings))
	}
}

func TestIBANDetector_FollowedByAlpha(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	// IBAN followed by alpha should not match.
	findings := d.Scan([]byte("DE89370400440532013000x"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for IBAN followed by alpha, want 0", len(findings))
	}
}

func TestIBANDetector_WrongLength(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	// DE expects 22 chars; provide only 20 (wrong length after country+check).
	findings := d.Scan([]byte("DE89370400440532"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for wrong length IBAN, want 0", len(findings))
	}
}

func TestIBANDetector_TrailingSpace(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	// IBAN followed by trailing spaces should still be detected after trimming.
	findings := d.Scan([]byte("DE89370400440532013000   "))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if "DE89370400440532013000   "[findings[0].Start:findings[0].End] != "DE89370400440532013000" {
		t.Errorf("matched text = %q, want %q", "DE89370400440532013000   "[findings[0].Start:findings[0].End], "DE89370400440532013000")
	}
}

func TestIBANDetector_HintsNilAlwaysScan(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	hints := d.Hints()
	// nil hints means the Scanner always runs IBAN detection,
	// so no country code can be silently missed.
	if hints != nil {
		t.Errorf("Hints() = %v, want nil (always scan)", hints)
	}
}

func TestIBANDetector_PreviouslyMissedCountry(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	// Albania (AL) was not in the old Hints() list. Verify it is detected.
	findings := d.Scan([]byte("AL42000000000000000000000000"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings for Albanian IBAN, want 1", len(findings))
	}
	matched := "AL42000000000000000000000000"[findings[0].Start:findings[0].End]
	if strings.ToUpper(matched[:2]) != "AL" {
		t.Errorf("CountryCode = %q, want AL", strings.ToUpper(matched[:2]))
	}
}

func TestIBANDetector_LowercaseIBAN(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	tests := []struct {
		name            string
		input           string
		wantRaw         string
		wantCountryCode string
		wantLen         int
	}{
		{
			name:            "lowercase German IBAN",
			input:           "de89370400440532013000",
			wantLen:         1,
			wantRaw:         "de89370400440532013000",
			wantCountryCode: "DE",
		},
		{
			name:            "lowercase British IBAN with mixed case BBAN",
			input:           "gb29nwbk60161331926819",
			wantLen:         1,
			wantRaw:         "gb29nwbk60161331926819",
			wantCountryCode: "GB",
		},
		{
			name:            "mixed case country code",
			input:           "De89370400440532013000",
			wantLen:         1,
			wantRaw:         "De89370400440532013000",
			wantCountryCode: "DE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen > 0 {
				if tt.input[findings[0].Start:findings[0].End] != tt.wantRaw {
					t.Errorf("matched text = %q, want %q", tt.input[findings[0].Start:findings[0].End], tt.wantRaw)
				}
				matched := tt.input[findings[0].Start:findings[0].End]
				if strings.ToUpper(matched[:2]) != tt.wantCountryCode {
					t.Errorf("CountryCode = %q, want %q", strings.ToUpper(matched[:2]), tt.wantCountryCode)
				}
			}
		})
	}
}

func TestIBANDetector_MultipleIBANs(t *testing.T) {
	t.Parallel()

	d := NewIBAN()
	// Use newline separator; spaces between IBANs would be consumed by the greedy extractor.
	findings := d.Scan([]byte("DE89370400440532013000\nGB29NWBK60161331926819"))
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
}

func TestIBANFollowingWord(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{sampleIBAN, "GB82 WEST 1234 5698 7654 32"} {
		for _, suffix := range []string{" y", " today", " 123"} {
			got := NewIBAN().Scan([]byte("to " + raw + suffix))
			if len(got) != 1 || ("to " + raw + suffix)[got[0].Start:got[0].End] != raw {
				t.Errorf("%q: got %v", raw+suffix, got)
			}
		}
	}
}

// Registry fields are independent fixtures from SWIFT release 103. Generated
// BBANs follow each country's character classes; national account checksums are
// outside the detector's documented country-length/MOD97 contract.
func TestIBANRegistryExamples(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/iban-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var countries []struct {
		Country   string `json:"country"`
		Structure string `json:"structure"`
		Example   string `json:"example"`
		Length    int    `json:"length"`
	}
	if err := json.Unmarshal(data, &countries); err != nil {
		t.Fatal(err)
	}
	if len(countries) != 89 {
		t.Fatal("incomplete registry fixture")
	}
	for _, country := range countries {
		t.Run(country.Country, func(t *testing.T) {
			t.Parallel()
			got := NewIBAN().Scan([]byte(country.Example))
			if len(got) != 1 || country.Example[got[0].Start:got[0].End] != country.Example || len(country.Example) != country.Length {
				t.Fatalf("registry example rejected: %s", country.Example)
			}
		})
	}
}

func TestIBANReservedCheckDigits(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"DE00100100100000000067", "DE01100100100000000049", "DE99100100100000000031"} {
		t.Run(value[:4], func(t *testing.T) {
			t.Parallel()
			if got := NewIBAN().Scan([]byte(value)); len(got) != 0 {
				t.Fatalf("reserved check digits accepted: %v", got)
			}
		})
	}
}

func TestIbanRejectedBoundaries(t *testing.T) {
	t.Parallel()
	if validateIBANMod97([]byte("GB82WEST1234569876543!")) {
		t.Fatal("invalid IBAN byte accepted")
	}
}

// ibanReferenceScan is the scan that tried every start, kept to check that
// looking for the check digits first finds the same IBANs.
func ibanReferenceScan(data []byte) []Finding {
	var findings []Finding
	for i := 0; i < len(data)-4; i++ {
		if !ibanPrefixAt(data, i) {
			continue
		}
		expectedLen, ok := ibanCountryLength(string([]byte{ascii.ToUpper(data[i]), ascii.ToUpper(data[i+1])}))
		if !ok {
			continue
		}
		chars, end := extractIBANChars(data, i, expectedLen)
		if len(chars) != expectedLen || (end < len(data) && ascii.IsAlphaNum(data[end])) || !validateIBANMod97(chars) {
			continue
		}
		findings = append(findings, Finding{DetectorName: NameIBAN, Start: i, End: end, Confidence: 0.95})
		i = end - 1
	}
	return findings
}

func TestIBANScanMatchesEveryStartReference(t *testing.T) {
	t.Parallel()
	// #nosec G404 -- Fixed seed for reproducible synthetic tests.
	rng := rand.New(rand.NewPCG(7, 97))
	parts := []string{"DE89370400440532013000", "de89 3704 0044 0532 0130 00", "GB82WEST12345698765432", "DE89", "x", "A", "1", "12", " ", "-", "INFO GET /health status=ok", "\xff"}
	for range 5000 {
		var b strings.Builder
		for range rng.IntN(8) {
			b.WriteString(parts[rng.IntN(len(parts))])
		}
		data := []byte(b.String())
		if got, want := NewIBAN().Scan(data), ibanReferenceScan(data); !slices.Equal(got, want) {
			t.Fatalf("Scan(%q) = %v, want %v", data, got, want)
		}
	}
}
