package embargo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/bits"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

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

func TestOutputJapaneseSeparators(t *testing.T) {
	t.Parallel()
	s := NewScanner()
	for _, v := range []string{
		"０９０－１２３４－５６７８", // U+FF0D: masked (control)
		"０９０−１２３４−５６７８", // U+2212 MINUS SIGN
		"０９０　１２３４　５６７８", // U+3000 IDEOGRAPHIC SPACE
		"４１１１　１１１１　１１１１　１１１１",
		"４１１１−１１１１−１１１１−１１１１",
		"4111‑1111‑1111‑1111", // U+2011 NON-BREAKING HYPHEN
		"4111–1111–1111–1111", // U+2013 EN DASH
		"１２３４　５６７８　９０１８",      // My Number
	} {
		var out bytes.Buffer
		slog.New(NewSlogHandler(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}}), s)).Info("signup", "note", v)
		got := strings.TrimSpace(out.String())
		t.Logf("%s", got)
		if strings.Contains(got, v) {
			t.Errorf("unmasked: %q", v)
		}
	}
}

func TestOutputInvisibleSeparators(t *testing.T) {
	t.Parallel()
	s := NewScanner()
	for _, v := range []string{
		"4111\u200b1111\u200b1111\u200b1111", // ZERO WIDTH SPACE
		"4111 1111 1111 1111",                // NO-BREAK SPACE
		"4111 1111 1111 1111",                // NARROW NO-BREAK SPACE
		"4111\u00ad1111\u00ad1111\u00ad1111", // SOFT HYPHEN
		"AKIA\u200bIOSFODNN7EXAMPLE",
		"AKIA\u200b\u00a0\u202f\u00adIOSFODNN7EXAMPLE",
		"4111\u200b\u00a0\u202f\u00ad111111111111",
	} {
		got := Mask(v, s.ScanString(v))
		t.Logf("%+q -> %+q", v, got)
		if got == v {
			t.Errorf("unmasked: %+q", v)
		}
	}
}

// Derive candidates from the Go toolchain's Unicode tables, including future additions.
func unicodeSeparatorRunes() []rune {
	var result []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.Is(unicode.Pd, r) || unicode.Is(unicode.Zs, r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Sm, r) && unicode.Is(unicode.Dash, r) {
			result = append(result, r)
		}
	}
	return result
}

func TestUnicodeCategoryMasking(t *testing.T) {
	t.Parallel()
	for _, r := range unicodeSeparatorRunes() {
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			t.Parallel()
			for _, tc := range []struct {
				kind  Kind
				parts []string
			}{
				{KindPAN, []string{"4111", "1111", "1111", "1111"}},
				{KindJPPhone, []string{"090", "1234", "5678"}},
				{KindMyNumber, []string{"1234", "5678", "9018"}},
				{KindAWSKey, []string{"AKIA", "IOSFODNN7EXAMPLE"}},
			} {
				// ASCII spaces and hyphens are actual token delimiters, not obfuscation.
				if tc.kind == KindAWSKey && (r == ' ' || r == '-') {
					continue
				}
				for _, repetitions := range []int{1, 3} {
					sep := strings.Repeat(string(r), repetitions)
					if (r == ' ' || r == '-') && repetitions > 1 {
						continue
					}
					raw := strings.Join(tc.parts, sep)
					input := "記録: " + raw + "!"
					findings := NewScanner(WithKinds(tc.kind)).ScanString(input)
					if got := Mask(input, findings); got != "記録: [REDACTED]!" {
						t.Errorf("%s %U x%d: %q => %q", tc.kind, r, repetitions, raw, got)
					}
				}
			}
		})
	}
}

func TestScanCanceledBetweenDetectors(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithAll())
	for checkpoint := 2; checkpoint <= len(scanner.detectors)+1; checkpoint++ {
		calls := 0
		findings := scanner.scan([]byte("email alice@example.com card 4111111111111111"), func() error {
			calls++
			if calls >= checkpoint {
				return context.Canceled
			}
			return nil
		})
		if len(findings) != 0 || calls != checkpoint {
			t.Fatalf("checkpoint %d returned %d findings after %d cancellation checks", checkpoint, len(findings), calls)
		}
	}
}

//nolint:gocognit // Keep the independent rendering cross-product and literal formats together.
func TestCredentialRenderingProperty(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindCredential))
	for n := range 12 {
		secret := fmt.Sprintf("opaqueFixture%02dxYz", n)
		for _, key := range []string{credentialFixtureKey, "token", "api_key", "Authorization", "Proxy-Authorization", "access_token", "refresh_token", "id_token", "x-api-key", "DB_PASSWORD", "Private-Token", "client_secret", "auth_token"} {
			schemes := []string{""}
			if strings.Contains(key, "Authorization") {
				schemes = []string{"Bearer ", "Basic ", "bEaReR "}
			}
			for _, scheme := range schemes {
				value := scheme + secret
				forms := []string{key + "=" + value, key + "=[REDACTED]" + secret}
				for _, verb := range []string{"%v", fmtFieldVerb, fmtGoSyntaxVerb, "%q"} {
					forms = append(forms, fmt.Sprintf(verb, http.Header{key: {value, value}}), fmt.Sprintf(verb, url.Values{key: {value, value}}), fmt.Sprintf(verb, map[string]string{key: value}))
				}
				//nolint:errchkjson // Retain checked encoding failures as the fixture evolves.
				body, err := json.Marshal(map[string]string{key: value})
				if err != nil {
					t.Fatal(err)
				}
				forms = append(forms, string(body))
				for _, quote := range []func(string) string{strconv.Quote, func(s string) string { return fmt.Sprintf("%q", s) }, func(s string) string {
					//nolint:errchkjson // Retain checked encoding failures as the fixture evolves.
					b, e := json.Marshal(s)
					if e != nil {
						t.Fatal(e)
					}
					return string(b)
				}} {
					forms = append(forms, quote(string(body)), quote(quote(string(body))))
					if scheme != "" {
						forms = append(forms, quote(value), quote(quote(value)))
					}
				}
				for _, input := range forms {
					t.Run(fmt.Sprintf("%s/%d/%s", key, n, input), func(t *testing.T) {
						t.Parallel()
						got := Mask(input, scanner.ScanString(input))
						// An opaque alphabet prevents unrelated detectors from hiding the failure.
						if strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED]") {
							t.Fatalf("secret retained: %q => %q", input, got)
						}
					})
				}
			}
		}
	}
}

func TestEmbeddedIPv4WholeSpanProperty(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindIPAddr))
	for n := 1; n < 255; n += 13 {
		tail := fmt.Sprintf("203.0.113.%d", n)
		for _, prefix := range []string{"::ffff:", "::", "64:ff9b::", "2001:db8::ffff:"} {
			address := prefix + tail
			for _, form := range []string{address, "[" + address + "]", "[" + address + "]:51234"} {
				input := "remote=" + form
				got := scanner.ScanString(input)
				if len(got) != 1 || input[got[0].Start:got[0].End] != address {
					t.Errorf("not one complete span: %s: %+v", input, got)
				}
			}
		}
	}
}

const (
	credentialFixtureKey = "password"
	fmtGoSyntaxVerb      = "%#v"
	fmtFieldVerb         = "%+v"
)

func TestEscapedCredentialFragments(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindCredential))
	for _, secret := range []string{"opaqueHead\"opaqueTail", `opaqueHead\opaqueTail`, "opaqueHead\nopaqueTail", "[REDACTED]opaqueTail"} {
		// Each suffix must disappear even when the secret contains a quote or bracket.
		input := `{"password":` + strconv.Quote(secret) + `}`
		for range 3 {
			got := Mask(input, scanner.ScanString(input))
			if strings.Contains(got, "opaqueHead") || strings.Contains(got, "opaqueTail") {
				t.Errorf("escaped secret fragment retained: %q => %q", input, got)
			}
			input = strconv.Quote(input)
		}
		for _, verb := range []string{"%v", fmtFieldVerb, fmtGoSyntaxVerb, "%q"} {
			input = fmt.Sprintf(verb, url.Values{credentialFixtureKey: {secret, secret}})
			got := Mask(input, scanner.ScanString(input))
			if strings.Contains(got, "opaqueHead") || strings.Contains(got, "opaqueTail") {
				t.Errorf("slice fragment retained: %q => %q", input, got)
			}
		}
	}
}
