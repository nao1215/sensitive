package tests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/sha3"
	"pgregory.net/rapid"

	"github.com/nao1215/embargo"
)

// Each draw is visible to rapid's shrinker; no opaque PRNG seeds are used.
func chars(t *rapid.T, alphabet string, n int) string {
	return string(rapid.SliceOfN(rapid.SampledFrom([]byte(alphabet)), n, n).Draw(t, "characters"))
}

func digits(t *rapid.T, n int) string { return chars(t, "0123456789", n) }

func unicodeSeparators() []string {
	var result []string
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.Is(unicode.Pd, r) || unicode.Is(unicode.Zs, r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Sm, r) && unicode.Is(unicode.Dash, r) {
			result = append(result, string(r))
		}
	}
	return result
}

func changedDigit(raw string, i int) string {
	b := []byte(raw)
	b[i] = '0' + (b[i]-'0'+1)%10
	return string(b)
}

// Separators exclude token alphabet characters and line breaks. ScanLines has
// line-relative offsets; equivalence is intentionally asserted on one line.
func surroundingText(t *rapid.T) string {
	return chars(t, " ;,:=\t\"()[]{}", rapid.IntRange(0, 80).Draw(t, "context length"))
}

func check(t *rapid.T, d embargo.Detector, raw, label string) {
	prefix := surroundingText(t)
	if rapid.Bool().Draw(t, "encoded separator") {
		prefix += "v%" + rapid.SampledFrom([]string{"20", "09", "3D", "3d", "3A", "26", "22", "28", "29", "5B", "5D", "7B", "7D", "2C", "3B", "3F"}).Draw(t, "escape")
	}
	prefix += label
	suffix := surroundingText(t)
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
	// Sort-code grammar requires ASCII delimiters; interior obfuscation is tested separately.
	var separators []string
	for _, separator := range unicodeSeparators() {
		if len(separator) == 1 && separator[0] <= unicode.MaxASCII {
			separators = append(separators, separator)
		}
	}
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
					sep := rapid.SampledFrom(separators).Draw(t, "separator")
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

const (
	metamorphicMessageKey = "message"
	metamorphicCountKey   = "count"
	referenceIBANKind     = "iban"
	referenceMarker       = "[REDACTED]"
)

// These relations compare public results, without deriving expected detections
// from another copy of a parser. Context-sensitive formats need line boundaries.
func TestMetamorphicIndependentLines(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		lines := rapid.SliceOfN(rapid.SampledFrom([]string{
			"hello", "email=alice@example.com", "pan=4111111111111111", "password=synthetic-value",
			"endpoint=192.0.2.1", "IBAN GB82 WEST 1234 5698 7654 32", "SWIFT: DEUTDEFF", referenceMarker,
		}), 1, 12).Draw(t, "independent lines")
		scanner := embargo.NewScanner(embargo.WithAll())
		for _, line := range lines {
			checkLineRelations(t, scanner, line)
		}
		joined := strings.Join(lines, "\n")
		want := findingsByLine(scanner, lines)
		if got := scanner.ScanString(joined); !slices.Equal(got, want) {
			t.Fatalf("line composition: %q: %v != %v", joined, got, want)
		}
		slices.Reverse(lines)
		if got := scanner.ScanString(strings.Join(lines, "\n")); !slices.Equal(got, findingsByLine(scanner, lines)) {
			t.Fatal("reordering independent lines changed a finding")
		}
	})
}

type relationTB interface {
	Helper()
	Fatal(...any)
	Fatalf(string, ...any)
}

func findingsByLine(scanner *embargo.Scanner, lines []string) []embargo.Finding {
	var result []embargo.Finding
	offset := 0
	for _, line := range lines {
		for _, finding := range scanner.ScanString(line) {
			finding.Start += offset
			finding.End += offset
			result = append(result, finding)
		}
		offset += len(line) + 1
	}
	return result
}

func checkLineRelations(t relationTB, scanner *embargo.Scanner, line string) {
	t.Helper()
	original := scanner.ScanString(line)
	const prefix = "public prelude\n"
	shifted := scanner.ScanString(prefix + line + "\npublic epilogue")
	for i := range shifted {
		shifted[i].Start -= len(prefix)
		shifted[i].End -= len(prefix)
	}
	if !slices.Equal(original, shifted) {
		t.Fatal("unrelated lines changed a finding")
	}
	masked := embargo.Mask(line, original)
	if again := scanner.ScanString(masked); len(again) != 0 {
		t.Fatalf("mask exposes another finding: kinds=%v", again)
	}
	if embargo.Mask(masked, scanner.ScanString(masked)) != masked {
		t.Fatal("mask is not idempotent")
	}
}

func TestMetamorphicKindsAndPercent(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		kind := rapid.SampledFrom([]embargo.Kind{embargo.KindEmail, embargo.KindPAN, embargo.KindIPAddr}).Draw(t, "kind")
		other := rapid.SampledFrom([]embargo.Kind{embargo.KindCredential, embargo.KindMyNumber, embargo.KindIBAN}).Draw(t, "other")
		value := chars(t, "abcdefghijklmnopqrstuvwxyz", rapid.IntRange(1, 20).Draw(t, "length")) + "@example.com"
		raw := "value=(" + value + ") pan=4111111111111111 password=fake-value"
		a := embargo.NewScanner(embargo.WithKinds(kind)).ScanString(raw)
		b := embargo.NewScanner(embargo.WithKinds(other)).ScanString(raw)
		union := embargo.NewScanner(embargo.WithKinds(kind, other)).ScanString(raw)
		checkKindUnion(t, union, a, b)
		// Credential grammar intentionally sees original URL delimiters; arbitrary
		// percent encoding is only an invariant for built-ins that decode one layer.
		scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
		encoded := make([]byte, 0, len(value)*3)
		for _, c := range []byte(value) {
			encoded = append(encoded, '%', "0123456789ABCDEF"[c>>4], "0123456789ABCDEF"[c&15])
		}
		got := scanner.ScanString("(" + string(encoded) + ")")
		if len(got) != 1 || got[0].Start != 1 || got[0].End != 1+len(encoded) || got[0].Kind != embargo.KindEmail {
			t.Fatal("encoded finding does not cover original bytes")
		}
	})
}

func checkKindUnion(t relationTB, union, a, b []embargo.Finding) {
	t.Helper()
	want := make(map[embargo.Finding]bool)
	for _, finding := range append(a, b...) {
		want[finding] = true
	}
	if len(union) != len(want) {
		t.Fatal("kind union count")
	}
	for _, finding := range union {
		if !want[finding] {
			t.Fatal("kind selection changes finding")
		}
	}
}

// Encode every original byte; pre-escaped text is outside the one-layer relation.
func checkRealEmailEncoding(t relationTB, scanner *embargo.Scanner, line string) {
	t.Helper()
	if strings.Contains(line, "%") {
		return
	}
	encoded := make([]byte, 0, len(line)*3)
	for _, c := range []byte(line) {
		encoded = append(encoded, '%', "0123456789ABCDEF"[c>>4], "0123456789ABCDEF"[c&15])
	}
	want := scanner.ScanString(line)
	for i := range want {
		want[i].Start *= 3
		want[i].End *= 3
	}
	if got := scanner.Scan(encoded); !slices.Equal(got, want) {
		t.Fatal("real email percent relation changed spans")
	}
}

func checkIsolatedRealLines(t relationTB, scanner *embargo.Scanner, a, b string) {
	t.Helper()
	// Long clean separators keep bounded context windows inside their record.
	padding := "\n" + strings.Repeat(" ", 160) + "\n"
	lines := []string{padding + a + padding, padding + b + padding}
	for range 2 {
		if got := scanner.ScanString(strings.Join(lines, "\n")); !slices.Equal(got, findingsByLine(scanner, lines)) {
			t.Fatal("isolated real-line permutation changed findings")
		}
		slices.Reverse(lines)
	}
}

func TestMetamorphicJSONAndSlog(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// #nosec G101 -- Deliberately fake credentials exercise masking.
		value := map[string]any{"email": chars(t, "abcxyz", rapid.IntRange(1, 20).Draw(t, "name")) + "@example.com", "password": "opaque-fake-value", metamorphicCountKey: rapid.IntRange(0, 99).Draw(t, metamorphicCountKey), "nested": []any{"public", true, nil}}
		checkJSONPaths(t, value)
	})
}

func checkJSONPaths(t relationTB, value map[string]any) {
	t.Helper()
	scanner := embargo.NewScanner(embargo.WithAll())
	compact, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	masked, err := scanner.MaskJSON(compact)
	if err != nil {
		t.Fatal(err)
	}
	other, err := scanner.MaskJSON(pretty)
	if err != nil || !bytes.Equal(masked, other) {
		t.Fatal("JSON whitespace changes masked document")
	}
	var buffer bytes.Buffer
	handler := embargo.NewSlogHandler(slog.NewJSONHandler(&buffer, nil), scanner)
	record := slog.NewRecord(time.Time{}, slog.LevelInfo, "public event", 0)
	record.AddAttrs(slog.Any("value", value))
	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal(buffer.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(masked, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(event["value"], &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("slog and MaskJSON disagree")
	}
}

// Licensed data stays in the owner's cache. CI runs the synthetic generators;
// the measurement report records a full replay without committing raw public logs.
//
//nolint:paralleltest // This opt-in measurement reads the full corpus serially.
func TestMetamorphicRealLogs(t *testing.T) {
	cache := os.Getenv("EMBARGO_LOG_CACHE")
	if cache == "" {
		t.Skip("set EMBARGO_LOG_CACHE to the verified public-log cache")
	}
	scanner := embargo.NewScanner(embargo.WithAll())
	kinds := []embargo.Kind{
		embargo.KindPAN, embargo.KindEmail, embargo.KindJPPhone, embargo.KindMyNumber, embargo.KindJWT,
		embargo.KindAWSKey, embargo.KindIBAN, embargo.KindIPAddr, embargo.KindSWIFTBIC, embargo.KindABARouting,
		embargo.KindUKSortCode, embargo.KindCVV, embargo.KindCardExpiry, embargo.KindPaymentToken, embargo.KindBankAccount,
		embargo.KindACHTrace, embargo.KindMerchantID, embargo.KindBTC, embargo.KindETH, embargo.KindGitHubToken,
		embargo.KindSlackToken, embargo.KindGoogleAPIKey, embargo.KindPrivateKeyPEM, embargo.KindCredential,
		embargo.KindServiceToken, embargo.KindHighEntropy,
	}
	first := embargo.NewScanner(embargo.WithKinds(kinds[:13]...))
	second := embargo.NewScanner(embargo.WithKinds(kinds[13:]...))
	email := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	for _, name := range []string{"Apache/Apache.log", "Linux/Linux.log", "Android/Android_2k.log", "HDFS/HDFS_2k.log", "OpenSSH/OpenSSH.log", "Zookeeper/Zookeeper.log", "BGL/BGL_2k.log", "Spark/Spark_2k.log"} {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join(cache, name)) // #nosec G304 G703 -- Fixed corpus paths under the operator-selected cache.
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if closeErr := f.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}()
			reader := bufio.NewScanner(f)
			reader.Buffer(make([]byte, 4096), 16<<20)
			count := 0
			previous := ""
			for reader.Scan() {
				line := reader.Text()
				checkLineRelations(t, scanner, line)
				checkKindUnion(t, scanner.ScanString(line), first.ScanString(line), second.ScanString(line))
				checkRealEmailEncoding(t, email, line)
				if count > 0 && count <= 64 {
					checkIsolatedRealLines(t, scanner, previous, line)
				}
				previous = line
				checkJSONPaths(t, map[string]any{metamorphicMessageKey: line})
				count++
			}
			if err := reader.Err(); err != nil {
				t.Fatal(err)
			}
			t.Logf("checked %d lines", count)
		})
	}
}

func TestMaskIdempotentAllKinds(t *testing.T) {
	t.Parallel()
	separators := unicodeSeparators()
	// Empty adjacency and repeated punctuation are grammar constructions;
	// individual Unicode separators and ASCII punctuation come from categories.
	separators = append(separators, "", "..")
	for r := rune(0); r <= unicode.MaxASCII; r++ {
		if unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.IsSpace(r) {
			separators = append(separators, string(r))
		}
	}
	samples := allAccuracySamples(t, developmentAccuracySet)
	samples = append(samples, countrySamples(t, developmentAccuracySet)...)
	samples = append(samples, readGeneratedAccuracy[labeledAccuracySample](t, "testdata/credentials-development.jsonl")...)
	byKind := map[embargo.Kind][]string{}
	for _, sample := range samples {
		if len(sample.Expected) > 0 {
			byKind[sample.Kind] = append(byKind[sample.Kind], sample.Text)
		}
	}
	if len(byKind) != 37 {
		t.Fatal("every Kind needs positive adjacency fixtures")
	}
	for kind, inputs := range byKind {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			scanner := embargo.NewScanner(embargo.WithKinds(kind))
			rapid.Check(t, func(t *rapid.T) {
				left := rapid.SampledFrom(inputs).Draw(t, "left")
				right := rapid.SampledFrom(inputs).Draw(t, "right")
				separator := rapid.SampledFrom(separators).Draw(t, "separator")
				text := left + separator + right
				masked := embargo.Mask(text, scanner.ScanString(text))
				if again := embargo.Mask(masked, scanner.ScanString(masked)); masked != again {
					t.Fatalf("%s: %q -> %q -> %q", kind, text, masked, again)
				}
				document, err := json.Marshal(text)
				if err != nil {
					t.Fatal(err)
				}
				first, err := scanner.MaskJSON(document)
				if err != nil {
					t.Fatal(err)
				}
				second, err := scanner.MaskJSON(first)
				if err != nil || !bytes.Equal(first, second) {
					t.Fatalf("%s JSON: %s -> %s -> %s: %v", kind, document, first, second, err)
				}
			})
		})
	}
}

// The per-byte coverage oracle does not sort or merge intervals.
func TestMaskCoverageOracle(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		length := rapid.IntRange(1, 100).Draw(t, "text length")
		text := strings.Repeat("x", length)
		coverage := make([]bool, length)
		count := rapid.IntRange(0, 30).Draw(t, "span count")
		findings := make([]embargo.Finding, 0, count)
		for range count {
			start := rapid.IntRange(0, length-1).Draw(t, "start")
			end := rapid.IntRange(start+1, length).Draw(t, "end")
			findings = append(findings, embargo.Finding{Kind: "fixture", Start: start, End: end, Confidence: 1})
			for i := start; i < end; i++ {
				coverage[i] = true
			}
		}
		var want strings.Builder
		for _, covered := range coverage {
			if covered {
				//nolint:errcheck // strings.Builder writes always succeed.
				want.WriteByte('*')
			} else {
				//nolint:errcheck // strings.Builder writes always succeed.
				want.WriteByte('x')
			}
		}
		replace := func(_ embargo.Kind, v string) string { return strings.Repeat("*", len(v)) }
		before := slices.Clone(findings)
		if got := embargo.MaskFunc(text, findings, replace); got != want.String() {
			t.Fatalf("union %q != %q", got, want.String())
		}
		if !reflect.DeepEqual(findings, before) {
			t.Fatal("findings mutated")
		}
		slices.Reverse(findings)
		if got := embargo.MaskFunc(text, findings, replace); got != want.String() {
			t.Fatal("permutation changed union")
		}
	})
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

func TestQuintInputReplay(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("models/input.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Traces [][]struct {
			Op       string `json:"op"`
			Value    int    `json:"value"`
			Snapshot int    `json:"snapshot"`
			Failed   bool   `json:"failed"`
		} `json:"traces"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Traces) != 64 {
		t.Fatal("missing model traces")
	}
	values := []string{"", "model-alpha", "model-beta"}
	seen := map[string]bool{}
	for _, trace := range fixture.Traces {
		var input embargo.Input[[]byte]
		var snapshot embargo.Secret[[]byte]
		for _, state := range trace {
			seen[state.Op] = true
			var err error
			switch state.Op {
			case "init":
			case "scanA", "scanB":
				source := []byte(values[1])
				if state.Op == "scanB" {
					source = []byte(values[2])
				}
				err = input.Scan(source)
				source[0] = 'X'
			case "scanNil":
				err = input.Scan(nil)
			case "scanInvalid":
				err = input.Scan(42)
			case "text":
				err = input.UnmarshalText([]byte(values[1]))
			case "marker":
				err = input.UnmarshalText([]byte(referenceMarker))
			case "json":
				err = input.UnmarshalJSON([]byte(`"bW9kZWwtYWxwaGE="`))
			case "badJSON":
				err = input.UnmarshalJSON([]byte(`{"opaque-private-value":42}`))
			case "snapshot":
				snapshot = input.Secret()
			default:
				t.Fatal("unknown model operation")
			}
			if (err != nil) != state.Failed || (err != nil && err.Error() != "embargo: invalid input") {
				t.Fatalf("error contract after %s", state.Op)
			}
			if string(input.Secret().Reveal()) != values[state.Value] || string(snapshot.Reveal()) != values[state.Snapshot] {
				t.Fatalf("state mismatch after %s", state.Op)
			}
			if input.String() != referenceMarker || snapshot.String() != referenceMarker {
				t.Fatal("display revealed model state")
			}
		}
	}
	if len(seen) != 10 {
		t.Fatal("trace generation missed an Input operation")
	}
}

// JSON number grammar: optional minus, a nonzero integer prefix (or zero),
// optional fraction, and optional signed exponent. Decimal arithmetic is exact.
func equivalentNumber(t *rapid.T, integer string) string {
	if rapid.Bool().Draw(t, "omit fraction and exponent") {
		return integer
	}
	zeros := rapid.IntRange(0, 24).Draw(t, "trailing zero digits")
	digits := integer + strings.Repeat("0", zeros)
	point := rapid.IntRange(0, len(digits)).Draw(t, "decimal point")
	exponent := len(digits) - point - zeros
	mantissa := digits
	switch {
	case point == 0:
		mantissa = "0." + digits
	case point < len(digits):
		mantissa = digits[:point] + "." + digits[point:]
	case rapid.Bool().Draw(t, "zero fraction"):
		mantissa += ".000"
	}
	if exponent == 0 && rapid.Bool().Draw(t, "omit exponent") {
		return mantissa
	}
	sign := ""
	if exponent >= 0 && rapid.Bool().Draw(t, "exponent plus") {
		sign = "+"
	}
	exp := strconv.Itoa(exponent)
	if exponent < 0 {
		sign = "-"
		exp = strconv.Itoa(-exponent)
	}
	exp = strings.Repeat("0", rapid.IntRange(0, 3).Draw(t, "exponent leading zeros")) + exp
	return mantissa + rapid.SampledFrom([]string{"e", "E"}).Draw(t, "exponent case") + sign + exp
}

//nolint:gocognit // Keep the sign, equivalent-lexeme and real-logger dimensions together.
func TestJSONNumberGrammarAcrossLoggers(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithAll())
	rapid.Check(t, func(rt *rapid.T) {
		integer := rapid.SampledFrom([]string{"4111111111111111", "123456789018", "9007199254740993", "123", "12345678", "4" + digits(rt, 15), "121000358", "401236", "123456789", "123456789012345", "1" + digits(rt, rapid.IntRange(0, 32).Draw(rt, "digit count"))}).Draw(rt, "integer")
		key := rapid.SampledFrom([]string{"value", "payment card", "cvv", "bank account", "routing number", "sort code", "ach trace", "merchant id", "ssn", "sin", "resident id"}).Draw(rt, "context")
		for _, sign := range []string{"", "-"} {
			if len(scanner.ScanString(key+": "+sign+integer)) == 0 {
				continue
			}
			for range 4 {
				lexeme := sign + equivalentNumber(rt, integer)
				a, ok := new(big.Rat).SetString(lexeme)
				b, baseOK := new(big.Rat).SetString(sign + integer)
				if !ok || !baseOK || a.Cmp(b) != 0 || !json.Valid([]byte(lexeme)) {
					rt.Fatalf("invalid grammar/oracle: %q", lexeme)
				}
				input := []byte(`{"` + key + `":` + lexeme + `}`)
				masked, err := scanner.MaskJSON(input)
				if err != nil || loggerField(t, masked, key) != referenceMarker {
					rt.Fatalf("whole lexeme not masked: %s => %s (%v)", input, masked, err)
				}
				for _, name := range []string{loggerSlog, loggerZap, loggerZerolog, loggerLogrus} {
					out := loggerOutput(t, scanner, name, key, json.Number(lexeme))
					if loggerField(t, out, key) != referenceMarker {
						rt.Fatalf("%s retained lexeme: %s", name, out)
					}
				}
				invalid := []byte(`{"` + key + `":0` + integer + `}`)
				if out, err := scanner.MaskJSON(invalid); err == nil || len(out) != 0 {
					rt.Fatal("leading zero accepted")
				}
			}
		}
	})
}

func TestHTTPEncodedKeysAndCredentialHeadersProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		email := "person" + strconv.Itoa(rapid.IntRange(1, 999999).Draw(rt, "user")) + "@example.net"
		key := rapid.SampledFrom([]string{email, "4111 1111 1111 1111", "090-1234-5678"}).Draw(rt, "query key")
		credential := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+email))
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/?"+url.QueryEscape(key)+"=public", http.NoBody)
		request.Header.Set("Authorization", credential)
		request.Header.Set("Proxy-Authorization", credential)
		var out bytes.Buffer
		handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/?"+url.QueryEscape(key)+"=public")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}), slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner())
		handler.ServeHTTP(httptest.NewRecorder(), request)
		var record struct {
			RequestHeaders  map[string]any      `json:"request_headers"`
			ResponseHeaders map[string][]string `json:"response_headers"`
			Target          string              `json:"target"`
			Status          int                 `json:"status"`
		}
		if err := json.Unmarshal(out.Bytes(), &record); err != nil {
			rt.Fatal(err)
		}
		if record.Target != "/?[REDACTED]=public" || record.ResponseHeaders["Location"][0] != "/?[REDACTED]=public" || record.Status != http.StatusTemporaryRedirect {
			rt.Fatal("query/redirect semantics lost", out.String())
		}
		for _, header := range []string{"Authorization", "Proxy-Authorization"} {
			if record.RequestHeaders[header] != referenceMarker {
				rt.Fatal("credential header escaped", header)
			}
		}
	})
}

type propertyBytes []byte

func TestByteContentsBeforeEncoderProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		email := "person" + strconv.Itoa(rapid.IntRange(1, 999999).Draw(rt, "user")) + "@example.net"
		for _, value := range []any{[]byte(email), propertyBytes(email)} {
			for _, structured := range []bool{false, true} {
				var out bytes.Buffer
				var handler slog.Handler = slog.NewTextHandler(&out, nil)
				if structured {
					handler = slog.NewJSONHandler(&out, nil)
				}
				slog.New(embargo.NewSlogHandler(handler, embargo.NewScanner())).Info("event", "data", value)
				if strings.Contains(out.String(), email) || strings.Contains(out.String(), base64.StdEncoding.EncodeToString([]byte(email))) || !strings.Contains(out.String(), referenceMarker) {
					rt.Fatal("encoder hid raw bytes from inspection")
				}
			}
		}
	})
}

func TestHTTPWithheldSchemaProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		status := rapid.IntRange(200, 599).Draw(rt, "final status")
		count := rapid.IntRange(0, 16).Draw(rt, "headers")
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/?planted;private@example.com", http.NoBody)
		for index := range count {
			request.Header.Set("Planted-"+strconv.Itoa(index), "private@example.com")
		}
		var out bytes.Buffer
		handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Planted-Response", "private@example.com")
			w.WriteHeader(status)
		}), slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner())
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var record map[string]any
		if err := json.Unmarshal(out.Bytes(), &record); err != nil {
			rt.Fatal(err)
		}
		if len(record) != 6 || record["level"] != "INFO" || record["msg"] != "embargo: record withheld (masking error)" || record["withheld_attributes"] != float64(6) || record["status"] != float64(status) || response.Code != status {
			rt.Fatalf("unexpected withheld schema or changed response: %s", out.Bytes())
		}
		stamp, stampOK := record["time"].(string)
		duration, durationOK := record["duration"].(float64)
		if !stampOK || stamp == "" || !durationOK || duration < 0 || strings.Contains(out.String(), "planted") || strings.Contains(out.String(), "private@example.com") {
			rt.Fatalf("missing trusted metadata or unsafe field: %s", out.Bytes())
		}
	})
}
