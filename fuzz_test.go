package embargo_test

import (
	"bytes"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/detect"
)

func fuzzSeeds() []string {
	return []string{
		"us_ssn=663-27-1262",
		"us_itin=984-73-5739",
		"uk_nino=ZM 88 85 70 B",
		"uk_nhs=769 461 7519",
		"in_aadhaar=2587 2639 8415",
		"in_pan=ATTJE9054P",
		"br_cpf=860.174.949-61",
		"br_cnpj=40.771.605/5203-66",
		"cn_resident_id=510104199602017742",
		"kr_rrn=220329-2878073",
		"ca_sin=413-643-081",

		"password=forgotten", "sk-proj-" + strings.Repeat("Fake0", 8), "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg",
		"v%20021000021", "v%20123456789018", "v%0909012345678", "v%3A2001:db8::1", "v%３D021000021",
		"",
		"user tanaka@example.com paid with 4532015112830366",
		"payment for card 4532-0151-1283-0366 amount $99.99",
		"card ４５３２0151 1283 0366",
		"call 090-1234-5678 or 03-1234-5678 or 0120-123-456",
		"mynumber: 123456789018",
		"token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"key: AKIAIOSFODNN7EXAMPLE ASIAIOSFODNN7EXAMPLE",
		"iban GB82WEST12345698765432 DE89370400440532013000",
		"from 192.168.0.1 and 2001:db8::1 and ::ffff:10.0.0.1",
		"swift DEUTDEFF500 and BOFAUS3N",
		"routing 021000021",
		"sort code: 12-34-56",
		"CVV: 123 security code 4567",
		"exp 12/28 有効期限 01/2030",
		"key: sk_live_4eC39HqLyjWDarjtT1zdp7dc PAYID-ABCDEFGHIJKLMNOPQRSTUVWX sq0idp-abcdefghijklmnopqrstuv",
		"口座番号 1234567 bank account 12345678",
		"ACH trace 021000021123456",
		"merchant ID ABCDE12345FGHI6 TID 12345678",
		"send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
		"addr: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"GITHUB_TOKEN=ghp_" + strings.Repeat("a1B2", 9) + " github_pat_" + strings.Repeat("A", 22) + "_" + strings.Repeat("b", 59),
		// Assembled at run time so that secret scanners do not flag the file.
		"SLACK_TOKEN=xox" + "b-" + strings.Repeat("1234567890-", 2) + strings.Repeat("abcdefgh", 3),
		"GOOGLE_API_KEY=AIza" + strings.Repeat("Sy", 17) + "A",
		"-----BEGIN RSA PRIVATE KEY-----\r\nMIIE\r\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		strings.Repeat("a@", 64),
		strings.Repeat("0", 64),
		strings.Repeat("-", 64),
		"\xff\xfe@\x00\x80 4532015112830366\xc3",
		"exp 01/01/00",
	}
}

func builtinDetectors() []detect.Detector {
	return []detect.Detector{&detect.Credential{}, &detect.ServiceToken{}, &detect.HighEntropy{}, detect.NewPAN(), detect.NewEmail(), detect.NewJPPhone(), detect.NewMyNumber(), detect.NewJWT(), detect.NewAWSKey(), detect.NewIBAN(), detect.NewIPAddr(), detect.NewSWIFTBIC(), detect.NewABARouting(), detect.NewUKSortCode(), detect.NewCVV(), detect.NewCardExpiry(), detect.NewPaymentToken(), detect.NewBankAccount(), detect.NewACHTrace(), detect.NewMerchantID(), detect.NewBTC(), detect.NewETH(), detect.NewGitHubToken(), detect.NewSlackToken(), detect.NewGoogleAPIKey(), detect.NewPrivateKeyPEM(), detect.NewCountry("us_ssn"), detect.NewCountry("us_itin"), detect.NewCountry("uk_nino"), detect.NewCountry("uk_nhs"), detect.NewCountry("in_aadhaar"), detect.NewCountry("in_pan"), detect.NewCountry("br_cpf"), detect.NewCountry("br_cnpj"), detect.NewCountry("cn_resident_id"), detect.NewCountry("kr_rrn"), detect.NewCountry("ca_sin")}
}

type findingKey struct {
	name       embargo.Kind
	start, end int
	confidence float64
}

func keysOf(findings []embargo.Finding) map[findingKey]int {
	m := make(map[findingKey]int, len(findings))
	for _, f := range findings {
		m[findingKey{f.Kind, f.Start, f.End, f.Confidence}]++
	}
	return m
}

// FuzzScanner compares prefiltered scanning to every internal recognizer and checks
// byte/string equivalence, immutable input and valid original-input spans.
func FuzzScanner(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	scanner := embargo.NewScanner(embargo.WithAll())
	detectors := builtinDetectors()
	f.Fuzz(func(t *testing.T, text string) {
		checkEmbeddedSecret(t, text)
		data := []byte(text)
		before := bytes.Clone(data)
		got := scanner.Scan(data)
		if !bytes.Equal(data, before) || !reflect.DeepEqual(got, scanner.ScanString(text)) {
			t.Fatal("input or entrypoint changed")
		}
		want := make(map[findingKey]int)
		decoded, positions := percentOracle(text)
		for _, d := range detectors {
			input := decoded
			if d.Name() == "credential" {
				input = data
			}
			for _, v := range d.Scan(input) {
				if d.Name() == "credential" {
					want[findingKey{embargo.Kind(v.DetectorName), v.Start, v.End, v.Confidence}]++
					continue
				}
				want[findingKey{embargo.Kind(v.DetectorName), positions[v.Start], positions[v.End], v.Confidence}]++
			}
		}
		if !sameKeys(keysOf(got), want) {
			t.Fatal("hint filter changed matches")
		}
		for i, v := range got {
			if v.Kind == "" || v.Start < 0 || v.End <= v.Start || v.End > len(data) || v.Confidence < 0 || v.Confidence > 1 {
				t.Fatal("invalid finding")
			}
			if i > 0 && got[i-1].Start > v.Start {
				t.Fatal("position order")
			}
		}
	})
}

func TestAllBuiltinsHaveSeeds(t *testing.T) {
	t.Parallel()
	if got := len(builtinDetectors()); got != 37 {
		t.Fatalf("reference recognizers: got %d, want 37", got)
	}
	seen := map[embargo.Kind]bool{}
	for _, s := range fuzzSeeds() {
		for _, f := range embargo.NewScanner(embargo.WithAll()).ScanString(s) {
			seen[f.Kind] = true
		}
	}
	for _, d := range builtinDetectors() {
		if !seen[embargo.Kind(d.Name())] {
			t.Errorf("uncovered builtin %s", d.Name())
		}
	}
}

// FuzzScanLines checks that ScanLines reports, for every line, exactly what
// Scan reports on that line alone, with 1-based line numbers and the line's
// own bytes.
//
//nolint:gocognit // The line-stream oracle checks content, numbering, and omissions together against independent splitting.
func FuzzScanLines(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Add("a@example.com\n\n4532015112830366\r\nlast line without newline 192.168.0.1")
	scanner := embargo.NewScanner(embargo.WithAll())

	f.Fuzz(func(t *testing.T, text string) {
		checkEmbeddedSecret(t, text)
		type lineResult struct {
			findings map[findingKey]int
			line     string
		}
		got := make(map[int]lineResult)
		err := scanner.ScanLines(strings.NewReader(text), func(lineNum int, line []byte, findings []embargo.Finding) {
			if _, dup := got[lineNum]; dup {
				t.Fatalf("line %d reported twice", lineNum)
			}
			got[lineNum] = lineResult{line: string(line), findings: keysOf(findings)}
		})
		if err != nil {
			t.Fatalf("ScanLines: %v", err)
		}

		// bufio.ScanLines drops a trailing empty line and strips one "\r"
		// before each "\n"; mirror that to build the oracle.
		if text == "" {
			if len(got) != 0 {
				t.Fatalf("empty input reported lines: %v", got)
			}
			return
		}
		lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		for i, line := range lines {
			line = strings.TrimSuffix(line, "\r")
			want := scanner.ScanString(line)
			res, reported := got[i+1]
			if len(want) == 0 {
				if reported {
					t.Fatalf("line %d %q has no findings but was reported", i+1, line)
				}
				continue
			}
			if !reported {
				t.Fatalf("line %d %q has %d findings but was not reported", i+1, line, len(want))
			}
			if res.line != line {
				t.Fatalf("line %d: callback got %q, want %q", i+1, res.line, line)
			}
			if !sameKeys(res.findings, keysOf(want)) {
				t.Fatalf("line %d %q: ScanLines findings differ from Scan", i+1, line)
			}
		}
		for n := range got {
			if n < 1 || n > len(lines) {
				t.Fatalf("reported line number %d outside 1..%d", n, len(lines))
			}
		}
	})
}

func sameKeys(a, b map[findingKey]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// checkEmbeddedSecret lets fuzzing vary arbitrary surrounding log bytes while
// bracket/newline separators preserve the generated email's lexical boundaries.
func checkEmbeddedSecret(t *testing.T, context string) {
	t.Helper()
	raw := "user" + strconv.Itoa(len(context)) + "@example.com"
	text := context + "\n[" + raw + "]\n" + context
	s := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	found := false
	for _, f := range s.ScanString(text) {
		if text[f.Start:f.End] == raw && f.Start == len(context)+2 {
			found = true
		}
	}
	if !found {
		t.Fatal("embedded valid email lost")
	}
}

// percentOracle uses the standard library on individual escapes, independently
// of the production decoder, while preserving malformed sequences and '+'.
func percentOracle(text string) (data []byte, positions []int) {
	for i := 0; i < len(text); {
		positions = append(positions, i)
		if text[i] == '%' && len(text)-i >= 3 {
			if decoded, err := url.PathUnescape(text[i : i+3]); err == nil {
				data = append(data, decoded...)
				i += 3
				continue
			}
		}
		data = append(data, text[i])
		i++
	}
	return data, append(positions, len(text))
}
