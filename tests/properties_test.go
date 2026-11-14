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

	"github.com/nao1215/sensitive"
	"github.com/nao1215/sensitive/detector"
	"github.com/nao1215/sensitive/mask"
	"golang.org/x/crypto/sha3"
	"pgregory.net/rapid"
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
func check(t *rapid.T, d sensitive.Detector, raw, label string) {
	prefix := context(t)
	if rapid.Bool().Draw(t, "encoded separator") {
		prefix += "v%" + rapid.SampledFrom([]string{"20", "09", "3D", "3d", "3A", "26", "22", "28", "29", "5B", "5D", "7B", "7D", "2C", "3B", "3F"}).Draw(t, "escape")
	}
	prefix += label
	suffix := context(t)
	text := prefix + raw + suffix
	s := sensitive.NewScanner(sensitive.WithDetector(d))
	want := s.ScanString(text)
	if len(want) != 1 || want[0].RawValue != raw || want[0].Start != len(prefix) || want[0].End != len(prefix)+len(raw) {
		t.Fatalf("%s rejected/mislocated %q: %+v", d.Name(), text, want)
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
	got, err := s.ScanReader(&chunkReader{strings.NewReader(padded), chunk})
	if err != nil || !reflect.DeepEqual(expected, got) {
		t.Fatalf("ScanReader mismatch: %v", err)
	}
	var lines []sensitive.Finding
	err = s.ScanLines(&chunkReader{strings.NewReader(padded), chunk}, func(n int, line []byte, f []sensitive.Finding) {
		if n != 1 || string(line) != padded {
			t.Fatal("line changed")
		}
		lines = append(lines, f...)
	})
	if err != nil || !reflect.DeepEqual(expected, lines) {
		t.Fatalf("ScanLines mismatch: %v", err)
	}
	redacted := mask.MaskAll(text, want, mask.Redact)
	if redacted != prefix+strings.Repeat("*", len(raw))+suffix {
		t.Fatal("redaction changed context or leaked value")
	}
	if mask.MaskAll(redacted, want, mask.Redact) != redacted {
		t.Fatal("same-findings redaction is not idempotent")
	}
	if len(raw) > 4 && mask.MaskAll(text, want, mask.Last4) != prefix+strings.Repeat("*", len(raw)-4)+raw[len(raw)-4:]+suffix {
		t.Fatal("Last4 contract")
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
func rejects(t *rapid.T, d sensitive.Detector, raw string) {
	if got := d.Scan([]byte(raw)); len(got) != 0 {
		t.Fatalf("%s accepted near-miss %q: %+v", d.Name(), raw, got)
	}
}

func TestPAN(t *testing.T) {
	for _, spec := range []struct {
		prefix  string
		lengths []int
	}{
		{"4", []int{13, 16}}, {"51", []int{16}}, {"55", []int{16}}, {"2221", []int{16}}, {"2720", []int{16}},
		{"34", []int{15}}, {"37", []int{15}}, {"6011", []int{16}}, {"65", []int{16}}, {"3528", []int{16}}, {"3589", []int{16}}, {"36", []int{14, 15, 16}}, {"62", []int{16, 17, 18, 19}},
	} {
		t.Run(spec.prefix, func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				n := rapid.SampledFrom(spec.lengths).Draw(t, "PAN length")
				raw := spec.prefix + digits(t, n-len(spec.prefix)-1)
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
				d := detector.NewPAN()
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
	t.Run("my_number", func(t *testing.T) {
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
			d := detector.NewMyNumber()
			check(t, d, raw, "")
			rejects(t, d, changedDigit(raw, 11))
			rejects(t, d, raw+"0")
		})
	})
	t.Run("aba", func(t *testing.T) {
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
			d := detector.NewABARouting()
			check(t, d, raw, "")
			rejects(t, d, changedDigit(raw, 8))
			rejects(t, d, raw+"0")
		})
	})
}

func TestIBAN(t *testing.T) {
	data, err := os.ReadFile("../detector/testdata/iban-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var countries []struct {
		Country, Structure, Example string
		Length                      int
	}
	if err = json.Unmarshal(data, &countries); err != nil {
		t.Fatal(err)
	}
	if len(countries) != 89 {
		t.Fatal("registry incomplete")
	}
	for _, c := range countries {
		t.Run(c.Country, func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				var bbanBuilder strings.Builder
				for _, g := range regexp.MustCompile(`(\d+)!([nac])`).FindAllStringSubmatch(c.Structure, -1) {
					n, e := strconv.Atoi(g[1])
					if e != nil {
						t.Fatal(e)
					}
					bbanBuilder.WriteString(chars(t, map[string]string{"n": "0123456789", "a": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "c": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"}[g[2]], n))
				}
				bban := bbanBuilder.String()
				var number strings.Builder
				for _, r := range bban + c.Country + "00" {
					if r >= 'A' && r <= 'Z' {
						number.WriteString(strconv.Itoa(int(r-'A') + 10))
					} else {
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
				d := detector.NewIBAN()
				check(t, d, raw, "")
				rejects(t, d, changedDigit(raw, 3))
				rejects(t, d, raw[:len(raw)-1])
				rejects(t, d, raw+"0")
			})
		})
	}
}

func TestTokens(t *testing.T) {
	for _, family := range []string{"aws", "github", "slack", "google", "jwt", "pem", "swift", "sort"} {
		t.Run(family, func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
				var d sensitive.Detector
				var raw, bad, label string
				switch family {
				case "aws":
					d = detector.NewAWSKey()
					raw = rapid.SampledFrom([]string{"AKIA", "ASIA"}).Draw(t, "prefix") + chars(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 16)
					bad = raw[:19]
				case "github":
					d = detector.NewGitHubToken()
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
					d = detector.NewSlackToken()
					p := "xox" + chars(t, "bpaors", 1) + "-"
					raw = p + chars(t, alnum+"-", rapid.IntRange(10, 200).Draw(t, "body length"))
					bad = p + chars(t, alnum, 9)
				case "google":
					d = detector.NewGoogleAPIKey()
					raw = "AIza" + chars(t, alnum+"_-", 35)
					bad = raw[:38]
				case "jwt":
					d = detector.NewJWT()
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
					d = detector.NewPrivateKeyPEM()
					kind := rapid.SampledFrom([]string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"}).Draw(t, "kind")
					raw = "-----BEGIN " + kind + "-----"
					bad = strings.Replace(raw, "PRIVATE", "PUBLIC", 1)
				case "swift":
					d = detector.NewSWIFTBIC()
					raw = chars(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4) + rapid.SampledFrom([]string{"GB", "JP", "US", "DE", "FR"}).Draw(t, "country") + chars(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 2)
					if rapid.Bool().Draw(t, "branch") {
						raw += chars(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 3)
					}
					label = "SWIFT: "
					bad = raw[:4] + "00" + raw[6:]
				case "sort":
					d = detector.NewUKSortCode()
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

func TestBitcoin(t *testing.T) {
	for _, kind := range []string{"p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr"} {
		t.Run(kind, func(t *testing.T) {
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
				d := detector.NewBTC()
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
		d := detector.NewETH()
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
