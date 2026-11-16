package embargo

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"math"
	"math/bits"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

func TestScannerRecognitionRegressions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind        Kind
		text, value string
	}{
		{kind: KindUKSortCode, text: "sort code: 12 34 56", value: "12 34 56"},
		{kind: KindBankAccount, text: "acct no: 12345678", value: "12345678"},
		{kind: KindPAN, text: "card ４５３２０１５１１２８３０３６６", value: "４５３２０１５１１２８３０３６６"},
		{kind: KindJPPhone, text: "phone ０９０１２３４５６７８", value: "０９０１２３４５６７８"},
		{kind: KindCVV, text: "SECURITY CODE: 123", value: "123"},
		{kind: KindIBAN, text: "IBAN: PK36SCBL0000001123456702", value: "PK36SCBL0000001123456702"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			t.Parallel()
			got := NewScanner(WithKinds(tc.kind)).ScanString(tc.text)
			if len(got) != 1 || tc.text[got[0].Start:got[0].End] != tc.value {
				t.Fatalf("%v", got)
			}
		})
	}
	if got := NewScanner(WithKinds(KindIPAddr)).ScanString("2001:db8::1Z"); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestDocumentedConfidenceBoundary(t *testing.T) {
	t.Parallel()
	const documentedEmail = "alice@example.com"
	for _, fixture := range []struct {
		text      string
		kind      Kind
		threshold float64
	}{
		{documentedEmail, KindEmail, 1},
		{"alice@example.zzzz", KindEmail, 0.8},
		{"alice@ex..ample.com", KindEmail, 0.9},
		{"eyJ4IjoxfQ.e30.c2ln", KindJWT, 0.9},
	} {
		t.Run(fixture.text, func(t *testing.T) {
			t.Parallel()
			scanner := NewScanner(WithKinds(fixture.kind), WithMinConfidence(fixture.threshold))
			findings := scanner.ScanString(fixture.text)
			if len(findings) != 1 || findings[0].Confidence != fixture.threshold || Mask(fixture.text, findings) == fixture.text {
				t.Fatalf("inclusive threshold %g lost or changed score: %v", fixture.threshold, findings)
			}
		})
	}
}

func TestDefaultPolicyAndRawSensitiveKeys(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW", "123-45-6789"} {
		if got := NewScanner().ScanString(value); len(got) != 0 {
			t.Fatalf("default selected opt-in kind: %v", got)
		}
		if got := NewScanner(WithAll()).ScanString(value); len(got) == 0 {
			t.Fatal("WithAll omitted opt-in fixture")
		}
	}
	scanner := NewScanner(WithSensitiveKeys("recovery"))
	value := "recovery=opaque"
	findings := scanner.ScanString(value)
	if len(findings) != 1 || findings[0].Kind != KindCredential || Mask(value, findings) != "recovery=[REDACTED]" {
		t.Fatalf("custom key raw scan changed: %v", findings)
	}
}

func TestCountryDefinitionCorpus(t *testing.T) {
	t.Parallel()
	file, err := os.Open("tests/testdata/countries-development.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewScanner(file)
	scanners := map[Kind]*Scanner{}
	for reader.Scan() {
		var row struct {
			ID       string `json:"id"`
			Kind     Kind   `json:"kind"`
			Text     string `json:"text"`
			Expected []struct {
				Start int `json:"start"`
				End   int `json:"end"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(reader.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		// Public identifiers have valid syntax; their false positives are measured separately.
		if strings.Contains(row.ID, "/public-id/") {
			continue
		}
		scanner := scanners[row.Kind]
		if scanner == nil {
			scanner = NewScanner(WithKinds(row.Kind))
			scanners[row.Kind] = scanner
		}
		got := scanner.ScanString(row.Text)
		if len(got) != len(row.Expected) || (len(row.Expected) > 0 && (got[0].Start != row.Expected[0].Start || got[0].End != row.Expected[0].End)) {
			t.Errorf("%s: got %v, want %v", row.ID, got, row.Expected)
		}
	}
	if err := reader.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestCountryStructureRejections(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind  Kind
		value string
	}{
		{KindUSSSN, "000123456"},
		{KindUSSSN, "666123456"},
		{KindUSSSN, "900123456"},
		{KindUSSSN, "123004567"},
		{KindUSSSN, "123450000"},
		{KindUSITIN, "912491234"},
		{KindUSITIN, "912661234"},
		{KindUSITIN, "912891234"},
		{KindUSITIN, "912931234"},
		{KindUKNINO, "DD123456A"},
		{KindUKNINO, "AO123456A"},
		{KindUKNINO, "BG123456A"},
		{KindUKNINO, "AB123456E"},
		{KindUKNHS, "0000000000"},
		{KindUKNHS, "1000000010"},
		{KindBrazilCPF, "00000000000"},
		{KindBrazilCNPJ, "00000000000000"},
		{KindBrazilCNPJ, "12.abc.345/01DE-35"},
		{KindChinaResidentID, "11010120230230001X"},
		{KindChinaResidentID, "000101199001010010"},
		{KindChinaResidentID, "110101199001010000"},
		{KindKoreaRRN, "rrn=9902311000000"},
		{KindKoreaRRN, "rrn=0001015000000"},
	} {
		if got := NewScanner(WithKinds(tc.kind)).ScanString(tc.value); len(got) != 0 {
			t.Errorf("%s accepted %s: %v", tc.kind, tc.value, got)
		}
	}
}

func TestCountryRRNEighteenthCenturyAndFullWidth(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"rrn=0001019000000", "rrn=0001010000000"} {
		if got := NewScanner(WithKinds(KindKoreaRRN)).ScanString(value); len(got) != 1 {
			t.Fatal("explicit historical RRN structure missed")
		}
	}
	value := "記録 １２３-４５６-７８２ 完了"
	got := NewScanner(WithKinds(KindCanadaSIN)).ScanString(value)
	if len(got) != 1 || value[got[0].Start:got[0].End] != "１２３-４５６-７８２" {
		t.Fatal(got)
	}
}

func TestCountryOverlappingSIN(t *testing.T) {
	t.Parallel()
	input := "123-456-782-002"
	const want = "[REDACTED]"
	scanner := NewScanner(WithKinds(KindCanadaSIN))
	findings := scanner.ScanString(input)
	if len(findings) != 2 || findings[0].Start != 0 || findings[0].End != 11 || findings[1].Start != 4 || findings[1].End != 15 {
		t.Fatalf("overlapping SIN ranges: %v", findings)
	}
	if got := Mask(input, findings); got != want {
		t.Fatalf("overlap left bytes visible: %q", got)
	}
}

func TestEntropyIgnoresLogLocations(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindHighEntropy))
	for _, location := range []string{
		"/tmp/BuildCache-20261116/Projects/PaymentGateway/RequestDiagnostics/SentryIntegration_test.go",
		"/tmp/claude-1000/-home-nao-ghq-github-com-nao1215-scratchpad/emb-ogp/tests/sentry_integration_test.go",
		"/home/runner/work/embargo/embargo/tests/TestCompatibilityTable_Sentry_safe.go",
		`C:\Users\builder\source\PaymentGatewayIntegration2026\sentry_integration_test.go`,
		"com.example.PaymentGatewayIntegration2026.ProcessAuthorizationRequest",
		"https://logs.example.net/artifacts/PaymentGatewayIntegration2026/RequestDiagnosticOutput.log",
		"PaymentGatewayIntegration2026_RequestDiagnosticOutput.log",
		"cache/q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg/output.log",
		"com.example.q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg.Handler",
		"https://logs.example.net/q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg/output",
		"q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg.log",
	} {
		t.Run(location, func(t *testing.T) {
			t.Parallel()
			if got := scanner.ScanString(location); len(got) != 0 {
				t.Fatalf("location became a secret candidate: %v", got)
			}
		})
	}
}

func TestEntropyRequiresSelection(t *testing.T) {
	t.Parallel()
	const randomID = "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg"
	var zero Scanner
	for _, scanner := range []*Scanner{&zero, NewScanner()} {
		if len(scanner.ScanString(randomID)) != 0 {
			t.Fatal("default selected uncertain random tokens")
		}
	}
	for _, scanner := range []*Scanner{NewScanner(WithAll()), NewScanner(WithKinds(KindHighEntropy)), NewScanner(WithKinds(), WithAll())} {
		if got := scanner.ScanString(randomID); len(got) != 1 || got[0].Kind != KindHighEntropy {
			t.Fatal("explicit entropy selection was lost", got)
		}
	}
	var out bytes.Buffer
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&out, nil), NewScanner()))
	logger.Info(randomID, "password", "opaque-password")
	if !bytes.Contains(out.Bytes(), []byte(randomID)) || bytes.Contains(out.Bytes(), []byte("opaque-password")) {
		t.Fatal("default key/entropy policy was lost")
	}
}

func TestOperationalLogFalsePositives(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind Kind
		text string
	}{
		{KindSWIFTBIC, "workerEnv.init() ok /etc/httpd/conf/workers2.properties"},
		{KindSWIFTBIC, "Deleting file /mnt/hadoop/dfs/data/current/subdir58/blk_123"},
		{KindSWIFTBIC, "rhost=pokemon1.cs.example.net"},
		{KindPAN, "blockMap updated: blk_-3702595599317472079 size 67108864"},
		{KindPAN, "03-17 16:16:01.530 28601 28601 V AudioManager: querySoundEffectsEnabled"},
		{KindMyNumber, "03-17 16:15:06.211  1702 27353 D PowerManagerService: releasing"},
		{KindMyNumber, "rhost=217-159-208-230-dsl.example.net"},
		{KindJPPhone, "03-17 16:13:39.070  1702  1815 D WindowManager: startAnimation"},
		{KindABARouting, "eventTime=261851713, downTime=261851646"},
		{KindABARouting, "acquire lock=233570404, flags=0x1"},
		{KindABARouting, "ino=-268435446 scontext=system_u:system_r"},
		{KindCredential, "token=Token{a64f992 ActivityRecord{de9231d}"},
		{KindCredential, "Bad activity token: android.os.BinderProxy@2bd79ce"},
	} {
		t.Run(string(tc.kind)+"/"+tc.text, func(t *testing.T) {
			t.Parallel()
			if got := NewScanner(WithKinds(tc.kind)).ScanString(tc.text); len(got) != 0 {
				t.Fatalf("operational metadata became a secret: %v", got)
			}
		})
	}
}

func TestCredentialObjectSyntaxStillProtectsPasswords(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindCredential))
	for _, text := range []string{`password=Example@abcdef12`, `token="Example@abcdef12"`, `secret=Token{abcdef12`, `token=Example@nothex`} {
		if len(scanner.ScanString(text)) != 1 {
			t.Errorf("credential was missed: %s", text)
		}
	}
}

func TestCustomKeyStillFindsOpaqueText(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindCredential), WithSensitiveKeys("recovery_code"))
	const text = "recovery_code=opaque-recovery-code password=public-label"
	got := scanner.ScanString(text)
	if len(got) != 1 || text[got[0].Start:got[0].End] != "opaque-recovery-code" {
		t.Fatal("custom key did not replace the default text key selection")
	}
}

// TestLabeledRecall measures individual detectors, avoiding overlap suppression
// by WithAll. Every positive must be found and every negative must be rejected.
//
//nolint:gocognit // Keep each acceptance table and its assertions together for review.
func TestLabeledRecall(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/recall.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Detector string   `json:"detector"`
		Text     string   `json:"text"`
		Parts    []string `json:"parts"`
		Positive bool     `json:"positive"`
	}
	if err = json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	known := make(map[string]bool)
	for _, d := range builtinDetectors() {
		name := string(d.Name())
		known[name] = true
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := NewScanner(WithKinds(Kind(d.Name())))
			pos, neg, tp, fp := 0, 0, 0, 0
			for _, r := range rows {
				if r.Detector != name {
					continue
				}
				text := r.Text + strings.Join(r.Parts, "")
				found := len(s.ScanString(text)) > 0
				if r.Positive {
					pos++
					if found {
						tp++
					}
				} else {
					neg++
					if found {
						fp++
					}
				}
				if found != r.Positive {
					t.Errorf("label=%v text=%q found=%v", r.Positive, text, found)
				}
			}
			if pos == 0 || neg == 0 {
				t.Fatal("missing corpus stratum")
			}
			t.Logf("recall=%d/%d false_positives=%d/%d", tp, pos, fp, neg)
		})
	}
	for _, r := range rows {
		if !known[r.Detector] {
			t.Errorf("unknown detector %q", r.Detector)
		}
	}
}

type literalDetector []Finding

func (d literalDetector) Scan([]byte) []Finding { return slices.Clone(d) }

func TestScannerSelection(t *testing.T) {
	t.Parallel()
	const text = "alice@example.com 192.0.2.1 cvv: 123"
	all := NewScanner().ScanString(text)
	var zero Scanner
	if !reflect.DeepEqual(all, zero.ScanString(text)) || !reflect.DeepEqual(all, NewScanner(WithAll()).ScanString(text)) {
		t.Fatal("default and explicit all must agree")
	}
	for _, kind := range []Kind{KindEmail, KindIPAddr, KindCVV} {
		if !slices.ContainsFunc(all, func(f Finding) bool { return f.Kind == kind }) {
			t.Fatalf("default missing %s", kind)
		}
	}
	s := NewScanner(WithAll(), WithKinds(KindEmail, KindEmail))
	if got := s.ScanString(text); len(got) != 1 || got[0].Kind != KindEmail {
		t.Fatalf("selection: %v", got)
	}
	if got := NewScanner(WithKinds()).ScanString(text); len(got) != 0 {
		t.Fatal("empty selection enables builtins")
	}
}

func TestScannerOverlapsAndValidation(t *testing.T) {
	t.Parallel()
	a := Finding{Kind: "custom", Start: 0, End: 5, Confidence: .8}
	b := Finding{Kind: "other", Start: 1, End: 4, Confidence: 1}
	s := NewScanner(WithKinds(), WithDetector(literalDetector{b, a}))
	if got := s.ScanString("token"); !reflect.DeepEqual(got, []Finding{a, b}) {
		t.Fatal(got)
	}
	for _, score := range []float64{-1, 2, math.NaN(), math.Inf(1)} {
		t.Run("invalid score", func(t *testing.T) {
			t.Parallel()
			mustPanic(t, func() { NewScanner(WithMinConfidence(score)) })
		})
	}
	mustPanic(t, func() { NewScanner(WithKinds("unknown")) })
	mustPanic(t, func() { NewScanner(WithDetector(nil)) })
	var pointer *literalDetector
	mustPanic(t, func() { NewScanner(WithDetector(pointer)) })
	for _, f := range []Finding{{Kind: "x", End: 6}, {Kind: "x", Start: -1, End: 1}, {Kind: "x", End: 1, Confidence: math.NaN()}, {End: 1}} {
		t.Run("invalid finding", func(t *testing.T) {
			t.Parallel()
			mustPanic(t, func() {
				NewScanner(WithKinds(), WithDetector(literalDetector{f})).ScanString("token")
			})
		})
	}
}

func mustPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	fn()
}

func TestScannerMutationEdges(t *testing.T) {
	t.Parallel()
	equal := Finding{Kind: "a", Start: 0, End: 1, Confidence: .5}
	got := NewScanner(WithKinds(), WithDetector(literalDetector{equal}), WithMinConfidence(.5)).ScanString("x")
	if !slices.Equal(got, []Finding{equal}) {
		t.Fatal("inclusive confidence threshold", got)
	}
	for _, f := range []Finding{{Kind: "a", Start: 0, End: 0}, {Kind: "a", Start: 1, End: 1}, {Kind: "a", Start: 1, End: 0}} {
		mustPanic(t, func() {
			NewScanner(WithKinds(), WithDetector(literalDetector{f})).ScanString("xy")
		})
	}
	want := []Finding{
		{Kind: "z", Start: 0, End: 3, Confidence: .5},
		{Kind: "a", Start: 0, End: 2, Confidence: 1},
		{Kind: "a", Start: 0, End: 2, Confidence: .5},
		{Kind: "b", Start: 0, End: 2, Confidence: 1},
	}
	input := slices.Clone(want)
	slices.Reverse(input)
	got = NewScanner(WithKinds(), WithDetector(literalDetector(input))).ScanString("xyz")
	if !slices.Equal(got, want) {
		t.Fatal("sort tie breaking", got)
	}
}

//nolint:goconst // Keep each input and expected secret span together.
func TestCredentialSecretSpans(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ text, secret string }{
		{`password=forgotten-pass host=db.example database=orders`, "forgotten-pass"},
		{`{"apiKey":"a forgotten value","count":17}`, "a forgotten value"},
		{`Authorization: Bearer pretend-bearer-token`, "pretend-bearer-token"},
		{`Authorization: Basic ZmFrZTpmaWN0aXRpb3Vz`, "ZmFrZTpmaWN0aXRpb3Vz"},
		{`Cookie: session=forgotten; theme=dark`, "session=forgotten; theme=dark"},
		{`postgres://reader:fake%2Fpass%40word@db.example/orders?sslmode=require`, "fake%2Fpass%40word"},
		{`mysql://reader:forgotten@db.example/orders`, "forgotten"},
		{`reader:forgotten@tcp(db.example:3306)/orders`, "forgotten"},
		{`mongodb+srv://reader:forgotten@db.example/orders`, "forgotten"},
		{`redis://:forgotten@db.example/0`, "forgotten"},
		{`amqp://reader:forgotten@mq.example/vhost`, "forgotten"},
		{`https://bucket.example/file?X-Amz-Signature=pretend-signature&expires=17`, "pretend-signature"},
		{`https://blob.example/file?sig=pretend%2Bsignature%3D&sv=2025`, "pretend%2Bsignature%3D"},
		{`AccountName=demo;AccountKey=pretend-storage-key==;EndpointSuffix=core.windows.net`, "pretend-storage-key=="},
		{`{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n"}`, `-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n`},
		{`aws_secret_access_key=pretend-key`, "pretend-key"},
		{`TWILIO_AUTH_TOKEN=pretend-auth-token`, "pretend-auth-token"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			scanner := NewScanner(WithKinds(KindCredential))
			got := scanner.ScanString(tc.text)
			start := strings.Index(tc.text, tc.secret)
			if len(got) != 1 || got[0].Start != start || got[0].End != start+len(tc.secret) {
				t.Fatalf("got %v, want secret span [%d,%d)", got, start, start+len(tc.secret))
			}
			if masked := Mask(tc.text, got); masked != strings.Replace(tc.text, tc.secret, "[REDACTED]", 1) {
				t.Fatal(masked)
			}
		})
	}
}

func TestCredentialNegatives(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindCredential))
	for _, text := range []string{"passwordless=true", "token_count=17", "https://example.com/db", "reader@db.example", "password=", `password="[REDACTED]"`, `sigaction=normal`, `classification:public`} {
		if got := scanner.ScanString(text); len(got) != 0 {
			t.Errorf("%q: %v", text, got)
		}
	}
}

func TestCredentialEscapesAndCloudBodies(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ text, secret string }{
		{`api key = "forgotten"`, "forgotten"},
		{`AKIAIOSFODNN7EXAMPLE q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUgQx2A9cF6`, "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUgQx2A9cF6"},
		{"-----BEGIN PRIVATE KEY-----\nFAKE-KEY-BODY\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\nFAKE-KEY-BODY\n-----END PRIVATE KEY-----"},
	} {
		scanner := NewScanner(WithKinds(KindCredential, KindPrivateKeyPEM))
		masked := Mask(tc.text, scanner.ScanString(tc.text))
		if strings.Contains(masked, tc.secret) {
			t.Errorf("secret retained for %q", tc.text)
		}
	}
}

func TestCredentialMaskingIsIdempotent(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindCredential))
	for _, text := range []string{"postgres://reader:forgotten@db.example/orders", "password=forgotten", "Authorization: Bearer forgotten"} {
		masked := Mask(text, scanner.ScanString(text))
		if len(scanner.ScanString(masked)) != 0 {
			t.Fatal("marker detected as a credential")
		}
	}
}

func TestCredentialAssignmentDelimiters(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindCredential))
	for _, text := range []string{"failure (password=opaque)", "fields [token=opaque]", "record <secret=opaque>", `{"Authorization":"Bearer opaque"}`} {
		got := Mask(text, scanner.ScanString(text))
		if want := strings.Replace(text, "opaque", "[REDACTED]", 1); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}

func TestCredentialAWSContextDoesNotDuplicateAssignment(t *testing.T) {
	t.Parallel()
	value := "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUgQx2A9cF6"
	text := "AKIAIOSFODNN7EXAMPLE aws_secret_access_key=" + value
	got := NewScanner(WithKinds(KindCredential)).ScanString(text)
	if len(got) != 1 || text[got[0].Start:got[0].End] != value {
		t.Fatalf("expected one credential span, got %v", got)
	}
}

func TestCredentialProtocolBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ text, secret string }{
		{"postgres://token:short-secret@db.example/app", "short-secret"},
		{"postgres://alice:part;two@db.example/db", "part;two"},
		{"Authorization: Bearer  short-secret", "short-secret"},
		{"Authorization: Basic   ZmFrZTpmaWN0aXRpb3Vz", "ZmFrZTpmaWN0aXRpb3Vz"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			scanner := NewScanner(WithKinds(KindCredential))
			got := Mask(tc.text, scanner.ScanString(tc.text))
			if want := strings.Replace(tc.text, tc.secret, "[REDACTED]", 1); got != want {
				t.Errorf("got %q want %q", got, want)
			}
		})
	}
}

func TestDispatchRetainsMoreThan32Families(t *testing.T) {
	t.Parallel()
	scanner := &Scanner{}
	for range 37 {
		scanner.detectors = append(scanner.detectors, detect.NewMyNumber())
	}
	scanner.hintCache = buildHintCache(scanner.detectors)
	scanner.buildDispatch()
	if got := bits.OnesCount64(scanner.selectDetectors([]byte("123456789012"))); got != 37 {
		t.Fatalf("selected %d families, want 37", got)
	}
}
