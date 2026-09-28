package sensitive_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nao1215/sensitive"
	"github.com/nao1215/sensitive/detector"
)

// fuzzSeeds returns inputs that reach every built-in detector, plus a few
// shapes that stress the scanners' boundaries (full-width digits, invalid
// UTF-8, repeated pivots, CRLF).
func fuzzSeeds() []string {
	return []string{
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

// builtinDetectors returns a fresh instance of every built-in detector.
// Keep this in sync with WithAll: TestFuzzBuiltinDetectorsMatchesWithAll
// fails if a detector is added to one list but not the other.
func builtinDetectors() []sensitive.Detector {
	return []sensitive.Detector{
		detector.NewPAN(),
		detector.NewEmail(),
		detector.NewJPPhone(),
		detector.NewMyNumber(),
		detector.NewJWT(),
		detector.NewAWSKey(),
		detector.NewIBAN(),
		detector.NewIPAddr(),
		detector.NewSWIFTBIC(),
		detector.NewABARouting(),
		detector.NewUKSortCode(),
		detector.NewCVV(),
		detector.NewCardExpiry(),
		detector.NewPaymentToken(),
		detector.NewBankAccount(),
		detector.NewACHTrace(),
		detector.NewMerchantID(),
		detector.NewBTC(),
		detector.NewETH(),
		detector.NewGitHubToken(),
		detector.NewSlackToken(),
		detector.NewGoogleAPIKey(),
		detector.NewPrivateKeyPEM(),
	}
}

func TestFuzzBuiltinDetectorsMatchesWithAll(t *testing.T) {
	t.Parallel()

	// WithoutDedup and a single input that hits nothing still lets us compare
	// the registered set: scan an input seeded for every detector and make
	// sure every detector name WithAll reports is one builtinDetectors knows.
	known := make(map[sensitive.DetectorName]bool)
	for _, d := range builtinDetectors() {
		known[d.Name()] = true
	}
	all := sensitive.NewScanner(sensitive.WithAll(), sensitive.WithoutDedup())
	seen := make(map[sensitive.DetectorName]bool)
	for _, seed := range fuzzSeeds() {
		for _, f := range all.ScanString(seed) {
			seen[f.DetectorName] = true
			if !known[f.DetectorName] {
				t.Errorf("WithAll reported %q, which builtinDetectors does not list", f.DetectorName)
			}
		}
	}
	for name := range known {
		if !seen[name] {
			t.Errorf("no fuzz seed reaches detector %q", name)
		}
	}
}

// checkFindings verifies the invariants every finding must satisfy against
// the data it was produced from.
func checkFindings(t *testing.T, data []byte, findings []sensitive.Finding) {
	t.Helper()
	for _, f := range findings {
		if f.Start < 0 || f.End > len(data) || f.Start >= f.End {
			t.Fatalf("%s: position [%d:%d] outside input of %d bytes (%q)", f.DetectorName, f.Start, f.End, len(data), data)
		}
		if got := string(data[f.Start:f.End]); got != f.RawValue {
			t.Fatalf("%s: RawValue %q != data[%d:%d] %q", f.DetectorName, f.RawValue, f.Start, f.End, got)
		}
		if f.Confidence < 0 || f.Confidence > 1 {
			t.Fatalf("%s: confidence %v outside [0, 1]", f.DetectorName, f.Confidence)
		}
		if f.Kind() == "" {
			t.Fatalf("%s: built-in detector has no Kind", f.DetectorName)
		}
	}
}

// findingKey identifies a finding independently of its Detail pointer.
type findingKey struct {
	name       sensitive.DetectorName
	start, end int
	confidence float64
}

func keysOf(findings []sensitive.Finding) map[findingKey]int {
	m := make(map[findingKey]int, len(findings))
	for _, f := range findings {
		m[findingKey{f.DetectorName, f.Start, f.End, f.Confidence}]++
	}
	return m
}

// FuzzScanner checks the Scanner over arbitrary text:
//   - no panic, and every finding lies inside the input with RawValue equal to
//     the bytes it points at and a confidence in [0, 1];
//   - with dedup on (the default) no two findings overlap;
//   - a single detector never reports two overlapping findings;
//   - the hint pre-filter never hides a match: every finding a detector
//     returns when called directly is also returned by a Scanner holding only
//     that detector (the Detector.Hints contract says hints are exhaustive);
//   - ScanString, ScanReader and Scan agree;
//   - WithSortByPosition only reorders the default result.
func FuzzScanner(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	defaultScanner := sensitive.NewScanner(sensitive.WithAll())
	byPosition := sensitive.NewScanner(sensitive.WithAll(), sensitive.WithSortByPosition())
	noDedup := sensitive.NewScanner(sensitive.WithAll(), sensitive.WithoutDedup())
	detectors := builtinDetectors()
	single := make([]*sensitive.Scanner, len(detectors))
	for i, d := range detectors {
		single[i] = sensitive.NewScanner(sensitive.WithDetector(d), sensitive.WithoutDedup())
	}

	f.Fuzz(func(t *testing.T, text string) {
		data := []byte(text)

		raw := noDedup.Scan(data)
		checkFindings(t, data, raw)

		for i, d := range detectors {
			direct := d.Scan(data)
			checkFindings(t, data, direct)
			// Email is exempt: in "a@b.co@c.org" both "a@b.co" and
			// "b.co@c.org" are well-formed, and which one the writer meant
			// is not decidable, so the detector reports both and leaves the
			// choice to the Scanner's dedup.
			for a := 0; a < len(direct) && d.Name() != detector.NameEmail; a++ {
				for b := a + 1; b < len(direct); b++ {
					if direct[a].Start < direct[b].End && direct[b].Start < direct[a].End {
						t.Fatalf("%s: overlapping findings %q [%d:%d] and %q [%d:%d] in %q", d.Name(),
							direct[a].RawValue, direct[a].Start, direct[a].End,
							direct[b].RawValue, direct[b].Start, direct[b].End, text)
					}
				}
			}
			viaScanner := keysOf(single[i].Scan(data))
			for _, fd := range direct {
				k := findingKey{fd.DetectorName, fd.Start, fd.End, fd.Confidence}
				if viaScanner[k] == 0 {
					t.Fatalf("%s: hint pre-filter hides finding %q at [%d:%d] in %q", d.Name(), fd.RawValue, fd.Start, fd.End, text)
				}
			}
		}

		got := defaultScanner.Scan(data)
		checkFindings(t, data, got)
		byPos := byPosition.Scan(data)
		for i := 1; i < len(byPos); i++ {
			if byPos[i-1].End > byPos[i].Start {
				t.Fatalf("deduplicated findings overlap: %s[%d:%d] and %s[%d:%d]",
					byPos[i-1].DetectorName, byPos[i-1].Start, byPos[i-1].End,
					byPos[i].DetectorName, byPos[i].Start, byPos[i].End)
			}
			if byPos[i-1].Start > byPos[i].Start {
				t.Fatalf("WithSortByPosition returned Start %d before %d", byPos[i-1].Start, byPos[i].Start)
			}
		}
		if a, b := keysOf(got), keysOf(byPos); len(got) != len(byPos) || !sameKeys(a, b) {
			t.Fatalf("WithSortByPosition changed the set of findings: %v vs %v", got, byPos)
		}

		if s := defaultScanner.ScanString(text); !sameKeys(keysOf(s), keysOf(got)) {
			t.Fatalf("ScanString and Scan disagree on %q", text)
		}
		r, err := defaultScanner.ScanReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ScanReader: %v", err)
		}
		if !sameKeys(keysOf(r), keysOf(got)) {
			t.Fatalf("ScanReader and Scan disagree on %q", text)
		}
	})
}

// FuzzScanLines checks that ScanLines reports, for every line, exactly what
// Scan reports on that line alone, with 1-based line numbers and the line's
// own bytes.
func FuzzScanLines(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Add("a@example.com\n\n4532015112830366\r\nlast line without newline 192.168.0.1")
	scanner := sensitive.NewScanner(sensitive.WithAll())

	f.Fuzz(func(t *testing.T, text string) {
		type lineResult struct {
			line     string
			findings map[findingKey]int
		}
		got := make(map[int]lineResult)
		err := scanner.ScanLines(strings.NewReader(text), func(lineNum int, line []byte, findings []sensitive.Finding) {
			if _, dup := got[lineNum]; dup {
				t.Fatalf("line %d reported twice", lineNum)
			}
			got[lineNum] = lineResult{string(line), keysOf(findings)}
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
