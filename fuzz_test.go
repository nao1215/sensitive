package embargo

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/embargo/internal/detect"
)

func fuzzSeeds() []string {
	return []string{
		"password%3DopaqueFixture%26public%3Dvalue", `Authorization: Digest response="opaqueFixture"`, `Password:[]uint8{0x61, 0x62}`, `password=\x22opaqueFixture\x22`,
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

func builtinDetectors() []detect.Detector { return builtins(nil) }

type findingKey struct {
	name       Kind
	start, end int
	confidence float64
}

func keysOf(findings []Finding) map[findingKey]int {
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
	scanner := NewScanner(WithAll())
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
			if Kind(d.Name()) == KindCredential {
				for _, v := range credentialViewOracle(d, data, decoded, positions) {
					want[findingKey{Kind(v.DetectorName), v.Start, v.End, v.Confidence}]++
				}
				continue
			}
			for _, v := range d.Scan(decoded) {
				want[findingKey{Kind(v.DetectorName), positions[v.Start], positions[v.End], v.Confidence}]++
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
	seen := map[Kind]bool{}
	for _, s := range fuzzSeeds() {
		for _, f := range NewScanner(WithAll()).ScanString(s) {
			seen[f.Kind] = true
		}
	}
	for _, d := range builtinDetectors() {
		if !seen[Kind(d.Name())] {
			t.Errorf("uncovered builtin %s", d.Name())
		}
	}
}

// FuzzScanLines checks that ScanLines reports, for every line, exactly what
// Scan reports on that line plus multiline PEM intersections, with the line's
// own bytes.
//
//nolint:gocognit // The line-stream oracle checks content, numbering, and omissions together against independent splitting.
func FuzzScanLines(f *testing.F) {
	for _, label := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
		header, footer := "-----BEGIN "+label+"-----", "-----END "+label+"-----"
		for _, newline := range []string{"\n", "\r\n"} {
			for i := range len(header) {
				f.Add(percentFrameByte(header, i) + newline + "body" + newline + percentFrame(footer) + newline + "visible")
			}
			for i := range len(footer) {
				f.Add(percentFrame(header) + newline + "body" + newline + percentFrameByte(footer, i) + newline + "visible")
			}
		}
	}

	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Add("a@example.com\n\n4532015112830366\r\nlast line without newline 192.168.0.1")
	scanner := NewScanner(WithAll())

	f.Fuzz(func(t *testing.T, text string) {
		checkEmbeddedSecret(t, text)
		type lineResult struct {
			findings map[findingKey]int
			line     string
		}
		got := make(map[int]lineResult)
		err := scanner.ScanLines(strings.NewReader(text), func(lineNum int, line []byte, findings []Finding) {
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
		full := scanner.ScanString(text)
		offset := 0
		for i, line := range lines {
			advance := len(line) + 1
			line = strings.TrimSuffix(line, "\r")
			want := scanner.ScanString(line)
			for _, f := range full {
				if f.Kind == KindPrivateKeyPEM && f.Start < offset && f.End > offset && line != "" {
					want = append(want, Finding{Kind: KindPrivateKeyPEM, Start: 0, End: min(len(line), f.End-offset), Confidence: f.Confidence})
				}
			}
			offset += advance
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
func checkEmbeddedSecret(t *testing.T, surrounding string) {
	t.Helper()
	raw := "user" + strconv.Itoa(len(surrounding)) + "@example.com"
	text := surrounding + "\n[" + raw + "]\n" + surrounding
	s := NewScanner(WithKinds(KindEmail))
	found := false
	for _, f := range s.ScanString(text) {
		if text[f.Start:f.End] == raw && f.Start == len(surrounding)+2 {
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

func FuzzMask(f *testing.F) {
	f.Add("abcdef", 1, 4, 3, 5)
	f.Add("日本語", 0, 3, 3, 6)
	f.Fuzz(func(t *testing.T, text string, a, b, c, d int) {
		spans := []Finding{{Kind: "a", Start: a, End: b, Confidence: 1}, {Kind: "b", Start: c, End: d, Confidence: 1}}
		calls := 0
		got := MaskFunc(text, spans, func(_ Kind, v string) string { calls++; return strings.Repeat("*", len(v)) })
		invalid := a < 0 || b <= a || b > len(text) || c < 0 || d <= c || d > len(text)
		if invalid {
			//nolint:goconst // Assert the literal public redaction contract.
			if got != "[REDACTED]" || calls != 0 {
				t.Fatal("invalid spans passed")
			}
			return
		}
		want := []byte(text)
		for i := range want {
			if (i >= a && i < b) || (i >= c && i < d) {
				want[i] = '*'
			}
		}
		if got != string(want) {
			t.Fatal("union missed a byte")
		}
	})
}

//nolint:gocognit // One generated tree is checked through construction, masking and descent.
func FuzzJSONPaths(f *testing.F) {
	for _, seed := range []string{"ordinary", `quote" slash\`, "listener 0.0.0.0", "token=Class@deadbeef", "123456789012.example.invalid"} {
		f.Add(seed, uint8(3), true)
	}
	f.Fuzz(func(t *testing.T, value string, depth uint8, object bool) {
		if len(value) > 4096 {
			t.Skip()
		}
		var tree any = map[string]any{"password": value, budgetPublicKey: true}
		for range int(depth) % 70 {
			if object {
				tree = map[string]any{"child": tree}
			} else {
				tree = []any{tree}
			}
		}
		input, err := json.Marshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		output, err := NewScanner(WithKinds()).MaskJSON(input)
		if int(depth)%70 >= 64 {
			if err == nil || output != nil {
				t.Fatal("depth limit bypass")
			}
			return
		}
		if err != nil || !json.Valid(output) {
			t.Fatal("structured path broke JSON")
		}
		var got any
		if err := json.Unmarshal(output, &got); err != nil {
			t.Fatal(err)
		}
		for range int(depth) % 70 {
			if object {
				node, ok := got.(map[string]any)
				if !ok {
					t.Fatal("object shape changed")
				}
				got = node["child"]
			} else {
				node, ok := got.([]any)
				if !ok || len(node) != 1 {
					t.Fatal("array shape changed")
				}
				got = node[0]
			}
		}
		leaf, ok := got.(map[string]any)
		if !ok {
			t.Fatal("leaf shape changed")
		}
		if leaf["password"] != redactionMarker || leaf[budgetPublicKey] != true {
			t.Fatal("nested sensitive path lost or clean field changed")
		}
	})
}

const budgetPublicKey = "public"

// Budget checks run in the fuzz worker, where inputs are evaluated serially.
// The seed path also runs without t.Parallel so allocation counters are isolated.
func FuzzAdversarialBudgets(f *testing.F) {
	for _, seed := range []string{digitSeparatorRun, credentialPrefixRun, nestedPercentPrefix, ibanPrefixRun, "listener 0.0.0.0", "\"\\\n", exponentWhitespaceString, "-1e+00\t", "+01E-00 ", "001e00 ", "1e-04 "} {
		f.Add(seed, uint8(8))
	}
	f.Fuzz(func(t *testing.T, pattern string, repeat uint8) {
		if len(pattern) > 256 {
			t.Skip()
		}
		text := strings.Repeat(pattern, int(repeat)+1)
		document, err := json.Marshal(map[string]string{budgetPublicKey: text})
		if err != nil {
			t.Fatal(err)
		}
		scanner := NewScanner(WithAll())
		var buffer bytes.Buffer
		handler := NewSlogHandler(slog.NewJSONHandler(&buffer, nil), scanner)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		started := time.Now()
		Mask(text, scanner.ScanString(text))
		output, err := scanner.MaskJSON(document)
		if err != nil || !json.Valid(output) {
			t.Fatal("bounded JSON input failed")
		}
		if err := handler.Handle(context.Background(), slog.Record{Message: text}); err != nil {
			t.Fatal("bounded log event failed")
		}
		runtime.ReadMemStats(&after)
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatal("bounded input exceeded five-second processing budget")
		}
		if after.TotalAlloc-before.TotalAlloc > uint64(len(document))*512+8<<20 {
			t.Fatal("bounded input exceeded allocation amplification budget")
		}
		if bytes.Count(buffer.Bytes(), []byte{'\n'}) != 1 || !json.Valid(buffer.Bytes()) {
			t.Fatal("hostile message broke log framing")
		}
	})
}

func FuzzCredentialGrammar(f *testing.F) {
	for _, value := range []string{"synthetic", `quote" slash\`, "Class@deadbeef", "long-path/component", redactionMarker} {
		f.Add(value, uint8(0))
	}
	f.Fuzz(func(t *testing.T, value string, form uint8) {
		if len(value) > 4096 {
			t.Skip()
		}
		// JSON quoting preserves a valid assignment while fuzz changes its payload.
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		key := []string{"password", "secret", "api_key"}[int(form)%3]
		document := []byte(`{"` + key + `":` + string(raw) + `,"ok":true}`)
		scanner := NewScanner(WithKinds(KindCredential))
		output, err := scanner.MaskJSON(document)
		if err != nil || !json.Valid(output) || !bytes.Contains(output, []byte(`"ok":true`)) {
			t.Fatal("credential grammar broke JSON")
		}
		text := key + "=" + string(raw)
		masked := Mask(text, scanner.ScanString(text))
		if value != "" && value != redactionMarker && !strings.Contains(masked, redactionMarker) {
			t.Fatal("quoted credential escaped masking")
		}
	})
}
