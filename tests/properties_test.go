package tests

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
	"pgregory.net/rapid"

	"github.com/nao1215/embargo"
)

// Each draw is visible to rapid's shrinker; no opaque PRNG seeds are used.
func chars(t *rapid.T, alphabet string, n int) string {
	return string(rapid.SliceOfN(rapid.SampledFrom([]byte(alphabet)), n, n).Draw(t, "characters"))
}
func digits(t *rapid.T, n int) string { return chars(t, "0123456789", n) }
func changedDigit(raw string, i int) string {
	b := []byte(raw)
	b[i] = '0' + (b[i]-'0'+1)%10
	return string(b)
}

// Separators exclude token alphabet characters and line breaks. ScanLines has
// line-relative offsets; equivalence is intentionally asserted on one line.
func context(t *rapid.T) string {
	return chars(t, " ;,:=\t\"()[]{}", rapid.IntRange(0, 80).Draw(t, "context length"))
}

func check(t *rapid.T, d embargo.Detector, raw, label string) {
	prefix := context(t)
	if rapid.Bool().Draw(t, "encoded separator") {
		prefix += "v%" + rapid.SampledFrom([]string{"20", "09", "3D", "3d", "3A", "26", "22", "28", "29", "5B", "5D", "7B", "7D", "2C", "3B", "3F"}).Draw(t, "escape")
	}
	prefix += label
	suffix := context(t)
	text := prefix + raw + suffix
	s := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(d))
	want := s.ScanString(text)
	if len(want) != 1 || text[want[0].Start:want[0].End] != raw || want[0].Start != len(prefix) || want[0].End != len(prefix)+len(raw) {
		t.Fatalf("%s rejected/mislocated %q: %+v", "selected detector", text, want)
	}
	if !reflect.DeepEqual(want, s.Scan([]byte(text))) {
		t.Fatal("Scan differs")
	}
	offset := rapid.SampledFrom([]int{0, 1, 511, 512, 4095, 4096, 65535, 65536}).Draw(t, "buffer boundary") + rapid.IntRange(0, len(raw)).Draw(t, "offset")
	padded := strings.Repeat(" ", offset) + text
	expected := slices.Clone(want)
	for i := range expected {
		expected[i].Start += offset
		expected[i].End += offset
	}
	if !reflect.DeepEqual(expected, s.ScanString(padded)) {
		t.Fatal("offset changed detection")
	}
	chunk := rapid.IntRange(1, len(raw)+17).Draw(t, "reader chunk")
	var lines []embargo.Finding
	err := s.ScanLines(&chunkReader{strings.NewReader(padded), chunk}, func(n int, line []byte, f []embargo.Finding) {
		if n != 1 || string(line) != padded {
			t.Fatal("line changed")
		}
		lines = append(lines, f...)
	})
	if err != nil || !reflect.DeepEqual(expected, lines) {
		t.Fatalf("ScanLines mismatch: %v", err)
	}
	redacted := embargo.Mask(text, want)
	if redacted != prefix+"[REDACTED]"+suffix {
		t.Fatal("redaction changed context or leaked value")
	}
	if embargo.Mask(redacted, s.ScanString(redacted)) != redacted {
		t.Fatal("rescan redaction is not idempotent")
	}
	if len(raw) > 4 && embargo.MaskFunc(text, want, func(_ embargo.Kind, v string) string { return "[REDACTED]" + v[len(v)-4:] }) != prefix+"[REDACTED]"+raw[len(raw)-4:]+suffix {
		t.Fatal("last four replacement")
	}
}

type chunkReader struct {
	reader io.Reader
	size   int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(p) > r.size {
		p = p[:r.size]
	}
	return r.reader.Read(p)
}

func rejects(t *rapid.T, d embargo.Detector, raw string) {
	if got := d.Scan([]byte(raw)); len(got) != 0 {
		t.Fatalf("%s accepted near-miss %q: %+v", "selected detector", raw, got)
	}
}

func TestPAN(t *testing.T) {
	t.Parallel()
	for _, spec := range []struct {
		prefix  string
		lengths []int
	}{
		{prefix: "4", lengths: []int{13, 16}},
		{prefix: "51", lengths: []int{16}},
		{prefix: "55", lengths: []int{16}},
		{prefix: "2221", lengths: []int{16}},
		{prefix: "2720", lengths: []int{16}},
		{prefix: "34", lengths: []int{15}},
		{prefix: "37", lengths: []int{15}},
		{prefix: "6011", lengths: []int{16}},
		{prefix: "65", lengths: []int{16}},
		{prefix: "3528", lengths: []int{16}},
		{prefix: "3589", lengths: []int{16}},
		{prefix: "36", lengths: []int{14, 15, 16}},
		{prefix: "38", lengths: []int{14, 15, 16}},
		{prefix: "300", lengths: []int{14, 15, 16}},
		{prefix: "644", lengths: []int{16}},
		{prefix: "62", lengths: []int{16, 17, 18, 19}},
	} {
		t.Run(spec.prefix, func(t *testing.T) {
			t.Parallel()
			rapid.Check(t, func(t *rapid.T) {
				n := rapid.SampledFrom(spec.lengths).Draw(t, "PAN length")
				prefix := spec.prefix
				switch prefix {
				case "51":
					prefix = strconv.Itoa(rapid.IntRange(51, 55).Draw(t, "Mastercard prefix"))
				case "2221":
					prefix = strconv.Itoa(rapid.IntRange(2221, 2720).Draw(t, "Mastercard 2-series prefix"))
				case "3528":
					prefix = strconv.Itoa(rapid.IntRange(3528, 3589).Draw(t, "JCB prefix"))
				case "300":
					prefix = strconv.Itoa(rapid.IntRange(300, 305).Draw(t, "Diners prefix"))
				case "644":
					prefix = strconv.Itoa(rapid.IntRange(644, 649).Draw(t, "Discover prefix"))
				}
				raw := prefix + digits(t, n-len(prefix)-1)
				sum := 0
				for i := len(raw) - 1; i >= 0; i-- {
					v := int(raw[i] - '0')
					if (len(raw)-1-i)%2 == 0 {
						v *= 2
						if v > 9 {
							v -= 9
						}
					}
					sum += v
				}
				raw += strconv.Itoa((10 - sum%10) % 10)
				d := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN))
				check(t, d, raw, "")
				if got := d.Scan([]byte(raw)); got[0].Confidence < 0.99 {
					t.Fatal("valid Luhn confidence")
				}
				// PAN deliberately reports invalid Luhn candidates at lower confidence.
				bad := d.Scan([]byte(changedDigit(raw, len(raw)-1)))
				if len(bad) != 1 || bad[0].Confidence >= 0.99 {
					t.Fatal("invalid Luhn confidence")
				}
			})
		})
	}
}

func TestNumericChecksums(t *testing.T) {
	t.Parallel()
	t.Run("my_number", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			raw := digits(t, 11)
			sum := 0
			for i, w := range []int{6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2} {
				sum += int(raw[i]-'0') * w
			}
			c := (11 - sum%11) % 11
			if c == 10 {
				c = 0
			}
			raw += strconv.Itoa(c)
			d := embargo.NewScanner(embargo.WithKinds(embargo.KindMyNumber))
			check(t, d, raw, "")
			rejects(t, d, changedDigit(raw, 11))
			rejects(t, d, raw+"0")
		})
	})
	t.Run("aba", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			prefix := rapid.SampledFrom([]int{1, 12, 21, 32, 61, 72, 80}).Draw(t, "district")
			raw := fmt.Sprintf("%02d", prefix) + digits(t, 6)
			if raw == "00000000" {
				raw = "00000001"
			}
			sum := 0
			for i, b := range raw {
				sum += int(b-'0') * []int{3, 7, 1}[i%3]
			}
			raw += strconv.Itoa((10 - sum%10) % 10)
			d := embargo.NewScanner(embargo.WithKinds(embargo.KindABARouting))
			check(t, d, raw, "")
			rejects(t, d, changedDigit(raw, 8))
			rejects(t, d, raw+"0")
		})
	})
}

//nolint:gocognit // Keep the independent checksum encoder with the generated inputs it validates.
func TestIBAN(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../internal/detect/testdata/iban-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var countries []struct {
		Country   string `json:"country"`
		Structure string `json:"structure"`
		Example   string `json:"example"`
		Length    int    `json:"length"`
	}
	if err = json.Unmarshal(data, &countries); err != nil {
		t.Fatal(err)
	}
	if len(countries) != 89 {
		t.Fatal("registry incomplete")
	}
	for _, c := range countries {
		t.Run(c.Country, func(t *testing.T) {
			t.Parallel()
			rapid.Check(t, func(t *rapid.T) {
				var bbanBuilder strings.Builder
				for _, g := range regexp.MustCompile(`(\d+)!([nac])`).FindAllStringSubmatch(c.Structure, -1) {
					n, e := strconv.Atoi(g[1])
					if e != nil {
						t.Fatal(e)
					}
					//nolint:errcheck // strings.Builder writes always succeed.
					bbanBuilder.WriteString(chars(t, map[string]string{"n": "0123456789", "a": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "c": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"}[g[2]], n))
				}
				bban := bbanBuilder.String()
				var number strings.Builder
				for _, r := range bban + c.Country + "00" {
					if r >= 'A' && r <= 'Z' {
						//nolint:errcheck // strings.Builder writes always succeed.
						number.WriteString(strconv.Itoa(int(r-'A') + 10))
					} else {
						//nolint:errcheck // strings.Builder writes always succeed.
						number.WriteRune(r)
					}
				}
				n, ok := new(big.Int).SetString(number.String(), 10)
				if !ok {
					t.Fatal("encoder")
				}
				raw := fmt.Sprintf("%s%02d%s", c.Country, 98-new(big.Int).Mod(n, big.NewInt(97)).Int64(), bban)
				if len(raw) != c.Length {
					t.Fatal("registry length")
				}
				d := embargo.NewScanner(embargo.WithKinds(embargo.KindIBAN))
				check(t, d, raw, "")
				rejects(t, d, changedDigit(raw, 3))
				rejects(t, d, raw[:len(raw)-1])
				rejects(t, d, raw+"0")
			})
		})
	}
}

func TestTokens(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"aws", "github", "slack", "google", "jwt", "pem", "swift", "sort"} {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			rapid.Check(t, func(t *rapid.T) {
				const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
				var d embargo.Detector
				var raw, bad, label string
				switch family {
				case "aws":
					d = embargo.NewScanner(embargo.WithKinds(embargo.KindAWSKey))
					raw = rapid.SampledFrom([]string{"AKIA", "ASIA"}).Draw(t, "prefix") + chars(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 16)
					bad = raw[:19]
				case "github":
					d = embargo.NewScanner(embargo.WithKinds(embargo.KindGitHubToken))
					p := rapid.SampledFrom([]string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}).Draw(t, "prefix")
					if p == "github_pat_" {
						raw = p + chars(t, alnum+"_", rapid.IntRange(22, 200).Draw(t, "body length"))
						bad = p + chars(t, alnum, 21)
					} else {
						raw = p + chars(t, alnum, 36)
						bad = raw[:39]
						rejects(t, d, raw+chars(t, alnum, rapid.IntRange(1, 40).Draw(t, "excess length")))
					}
				case "slack":
					d = embargo.NewScanner(embargo.WithKinds(embargo.KindSlackToken))
					p := "xox" + chars(t, "bpaors", 1) + "-"
					raw = p + chars(t, alnum+"-", rapid.IntRange(10, 200).Draw(t, "body length"))
					bad = p + chars(t, alnum, 9)
				case "google":
					d = embargo.NewScanner(embargo.WithKinds(embargo.KindGoogleAPIKey))
					raw = "AIza" + chars(t, alnum+"_-", 35)
					bad = raw[:38]
				case "jwt":
					d = embargo.NewScanner(embargo.WithKinds(embargo.KindJWT))
					alg := rapid.SampledFrom([]string{"HS256", "RS256", "none"}).Draw(t, "algorithm")
					h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
					p := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + chars(t, alnum, rapid.IntRange(1, 200).Draw(t, "subject length")) + `"}`))
					sig := base64.RawURLEncoding.EncodeToString(rapid.SliceOfN(rapid.Byte(), 1, 128).Draw(t, "signature"))
					if alg == "none" {
						sig = ""
					}
					raw = h + "." + p + "." + sig
					bad = h + ".!invalid." + sig
				case "pem":
					d = embargo.NewScanner(embargo.WithKinds(embargo.KindPrivateKeyPEM))
					kind := rapid.SampledFrom([]string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"}).Draw(t, "kind")
					raw = "-----BEGIN " + kind + "-----"
					bad = strings.Replace(raw, "PRIVATE", "PUBLIC", 1)
				case "swift":
					d = embargo.NewScanner(embargo.WithKinds(embargo.KindSWIFTBIC))
					raw = chars(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4) + rapid.SampledFrom([]string{"GB", "JP", "US", "DE", "FR"}).Draw(t, "country") + chars(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 2)
					if rapid.Bool().Draw(t, "branch") {
						raw += chars(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 3)
					}
					label = "SWIFT: "
					bad = raw[:4] + "00" + raw[6:]
				case "sort":
					d = embargo.NewScanner(embargo.WithKinds(embargo.KindUKSortCode))
					sep := rapid.SampledFrom([]string{"-", " "}).Draw(t, "separator")
					raw = digits(t, 2) + sep + digits(t, 2) + sep + digits(t, 2)
					if strings.ReplaceAll(raw, sep, "") == "000000" {
						raw = "01" + raw[2:]
					}
					label = "sort code: "
					bad = raw[:len(raw)-1]
				}
				check(t, d, raw, label)
				rejects(t, d, bad)
			})
		})
	}
}

//nolint:gocognit // Keep the independent checksum encoder with the generated inputs it validates.
func TestBitcoin(t *testing.T) {
	t.Parallel()
	//nolint:goconst // Keep Bitcoin address family names explicit in the independent oracle.
	for _, kind := range []string{"p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			rapid.Check(t, func(t *rapid.T) {
				n := 20
				if kind == "p2wsh" || kind == "p2tr" {
					n = 32
				}
				payload := rapid.SliceOfN(rapid.Byte(), n, n).Draw(t, "program")
				var raw string
				if kind == "p2pkh" || kind == "p2sh" {
					v := byte(0)
					if kind == "p2sh" {
						v = 5
					}
					b := append([]byte{v}, payload...)
					h := sha256.Sum256(b)
					h = sha256.Sum256(h[:])
					b = append(b, h[:4]...)
					number := new(big.Int).SetBytes(b)
					var rev []byte
					for number.Sign() > 0 {
						r := new(big.Int)
						number.QuoRem(number, big.NewInt(58), r)
						rev = append(rev, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[r.Int64()])
					}
					for _, c := range b {
						if c != 0 {
							break
						}
						rev = append(rev, '1')
					}
					slices.Reverse(rev)
					raw = string(rev)
				} else {
					v := byte(0)
					if kind == "p2tr" {
						v = 1
					}
					raw = encodeWitness(v, payload)
				}
				d := embargo.NewScanner(embargo.WithKinds(embargo.KindBTC))
				check(t, d, raw, "")
				b := []byte(raw)
				if b[len(b)-1] == 'q' {
					b[len(b)-1] = 'p'
				} else {
					b[len(b)-1] = 'q'
				}
				rejects(t, d, string(b))
			})
		})
	}
}

// x/crypto supplies an independent Keccak oracle; it is test-only.
func TestEIP55(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 20, 20).Draw(t, "address")
		lower := hex.EncodeToString(b)
		h := sha3.NewLegacyKeccak256()
		if _, err := h.Write([]byte(lower)); err != nil {
			t.Fatal(err)
		}
		hash := hex.EncodeToString(h.Sum(nil))
		out := []byte(lower)
		for i, c := range out {
			if c >= 'a' && c <= 'f' && hash[i] >= '8' {
				out[i] -= 32
			}
		}
		raw := "0x" + string(out)
		d := embargo.NewScanner(embargo.WithKinds(embargo.KindETH))
		check(t, d, raw, "")
		rejects(t, d, raw+"0")
		// Uniform case is accepted by design, so a flip must leave mixed case.
		for i, c := range out {
			if c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
				out[i] ^= 32
				break
			}
		}
		changed := string(out)
		if changed != strings.ToLower(changed) && changed != strings.ToUpper(changed) {
			rejects(t, d, "0x"+changed)
		}
	})
}
