package sensitive_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nao1215/sensitive"
	"github.com/nao1215/sensitive/detector"
	"github.com/nao1215/sensitive/mask"
)

func TestScanner_Scan_emptyInput(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())
	findings := scanner.Scan(nil)
	if len(findings) != 0 {
		t.Errorf("Scan(nil) returned %d findings, want 0", len(findings))
	}

	findings = scanner.Scan([]byte{})
	if len(findings) != 0 {
		t.Errorf("Scan(empty) returned %d findings, want 0", len(findings))
	}
}

func TestScanner_Scan_noMatch(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())
	input := []byte("2024-01-15T10:30:00Z INFO server started on port 8080 request_id=abc123")
	findings := scanner.Scan(input)

	// This line contains no sensitive data — but some detectors might produce
	// low-confidence matches. We check there are no high-confidence findings.
	for _, f := range findings {
		if f.Confidence >= 0.6 {
			t.Errorf("unexpected high-confidence finding: %+v", f)
		}
	}
}

func TestScanner_ScanString_panDetection(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithPAN())
	findings := scanner.ScanString("card is 4532015112830366")

	panFindings := filterByDetector(findings, detector.NamePAN)
	if len(panFindings) != 1 {
		t.Fatalf("want 1 PAN finding, got %d", len(panFindings))
	}
	f := panFindings[0]
	if f.RawValue != "4532015112830366" {
		t.Errorf("RawValue = %q, want %q", f.RawValue, "4532015112830366")
	}
	if f.Confidence < 0.9 {
		t.Errorf("Confidence = %f, want >= 0.9", f.Confidence)
	}
}

func TestScanner_ScanString_emailDetection(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithEmail())
	findings := scanner.ScanString("contact tanaka@example.com for info")

	emailFindings := filterByDetector(findings, detector.NameEmail)
	if len(emailFindings) != 1 {
		t.Fatalf("want 1 email finding, got %d", len(emailFindings))
	}
	f := emailFindings[0]
	if f.RawValue != "tanaka@example.com" {
		t.Errorf("RawValue = %q, want %q", f.RawValue, "tanaka@example.com")
	}
}

func TestScanner_ScanString_multipleDetectors(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
	input := "user tanaka@example.com paid with 4532015112830366"
	findings := scanner.ScanString(input)

	panFindings := filterByDetector(findings, detector.NamePAN)
	emailFindings := filterByDetector(findings, detector.NameEmail)
	if len(panFindings) != 1 {
		t.Errorf("want 1 PAN finding, got %d", len(panFindings))
	}
	if len(emailFindings) != 1 {
		t.Errorf("want 1 email finding, got %d", len(emailFindings))
	}
}

func TestScanner_Scan_deduplication(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())
	findings := scanner.ScanString("card is 4532015112830366")

	// There should be only one PAN finding, even with WithAll() enabled.
	panFindings := filterByDetector(findings, detector.NamePAN)
	if len(panFindings) > 1 {
		t.Errorf("expected deduplicated findings, got %d PAN findings", len(panFindings))
	}
}

func TestNewScanner_noDetectors(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner()
	findings := scanner.ScanString("4532015112830366 tanaka@example.com")
	if len(findings) != 0 {
		t.Errorf("scanner with no detectors returned %d findings, want 0", len(findings))
	}
}

func TestScanner_WithJPPhone(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithJPPhone())
	findings := scanner.ScanString("TEL: 090-1234-5678")
	jpFindings := filterByDetector(findings, detector.NameJPPhone)
	if len(jpFindings) != 1 {
		t.Fatalf("want 1 JPPhone finding, got %d", len(jpFindings))
	}
}

func TestScanner_WithMyNumber(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithMyNumber())
	findings := scanner.ScanString("mynumber: 123456789018")
	myFindings := filterByDetector(findings, detector.NameMyNumber)
	if len(myFindings) != 1 {
		t.Fatalf("want 1 MyNumber finding, got %d", len(myFindings))
	}
}

func TestScanner_WithJWT(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithJWT())
	// #nosec G101 -- test token for JWT detection
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	findings := scanner.ScanString("token: " + token)
	jwtFindings := filterByDetector(findings, detector.NameJWT)
	if len(jwtFindings) != 1 {
		t.Fatalf("want 1 JWT finding, got %d", len(jwtFindings))
	}
}

func TestScanner_WithAWSKey(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAWSKey())
	findings := scanner.ScanString("key: AKIAIOSFODNN7EXAMPLE")
	awsFindings := filterByDetector(findings, detector.NameAWSKey)
	if len(awsFindings) != 1 {
		t.Fatalf("want 1 AWSKey finding, got %d", len(awsFindings))
	}
}

func TestScanner_WithIBAN(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithIBAN())
	findings := scanner.ScanString("IBAN: DE89370400440532013000")
	ibanFindings := filterByDetector(findings, detector.NameIBAN)
	if len(ibanFindings) != 1 {
		t.Fatalf("want 1 IBAN finding, got %d", len(ibanFindings))
	}
}

func TestScanner_WithIPAddr(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithIPAddr())
	findings := scanner.ScanString("host: 192.168.1.1")
	ipFindings := filterByDetector(findings, detector.NameIPAddr)
	if len(ipFindings) != 1 {
		t.Fatalf("want 1 IPAddr finding, got %d", len(ipFindings))
	}
}

func TestScanner_WithDetector(t *testing.T) {
	t.Parallel()

	// WithDetector with a custom regex detector.
	re := regexp.MustCompile(`CUSTOM-\d+`)
	d := detector.NewRegex("custom", re, [][]byte{[]byte("CUSTOM-")}, 0.8)
	scanner := sensitive.NewScanner(sensitive.WithDetector(d))
	findings := scanner.ScanString("CUSTOM-12345")
	if len(findings) != 1 {
		t.Fatalf("want 1 custom finding, got %d", len(findings))
	}
}

func TestScanner_HintFilterSkipsDetector(t *testing.T) {
	t.Parallel()

	// WithEmail on input without '@' should not trigger email detector.
	scanner := sensitive.NewScanner(sensitive.WithEmail())
	findings := scanner.ScanString("no email here")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when hint doesn't match, got %d", len(findings))
	}
}

func TestScanner_HintFilter_CaseInsensitive(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithACHTrace())
	findings := scanner.ScanString("TrAcE Number: 021000021123456")
	achFindings := filterByDetector(findings, detector.NameACHTrace)
	if len(achFindings) != 1 {
		t.Fatalf("want 1 ACHTrace finding, got %d", len(achFindings))
	}
}

func TestScanner_DedupOverlapping(t *testing.T) {
	t.Parallel()

	// Use two regex detectors that match overlapping regions to exercise dedup.
	// Detector A matches "ABCDEF" (positions 0-6) with confidence 0.5.
	// Detector B matches "CDEFGH" (positions 2-8) with confidence 0.9.
	// dedup should keep the higher confidence one.
	reA := regexp.MustCompile(`ABCDEF`)
	reB := regexp.MustCompile(`CDEFGH`)
	dA := detector.NewRegex("detA", reA, nil, 0.5)
	dB := detector.NewRegex("detB", reB, nil, 0.9)
	scanner := sensitive.NewScanner(
		sensitive.WithDetector(dA),
		sensitive.WithDetector(dB),
	)
	findings := scanner.ScanString("ABCDEFGH")
	// The two findings overlap [0:6] and [2:8]. dedup should keep only one.
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 after dedup", len(findings))
	}
	if findings[0].Confidence != 0.9 {
		t.Errorf("Confidence = %f, want 0.9 (higher confidence should win)", findings[0].Confidence)
	}
}

func TestScanner_DedupBridgingOverlap(t *testing.T) {
	t.Parallel()

	// A(0-6, conf=0.9), B(4-10, conf=0.5), C(8-14, conf=0.8).
	// A and C do NOT overlap directly, but B bridges them.
	// The dedup should keep both A and C, discarding only B.
	reA := regexp.MustCompile(`ABCDEF`)
	reB := regexp.MustCompile(`EFGHIJ`)
	reC := regexp.MustCompile(`IJKLMN`)
	dA := detector.NewRegex("detA", reA, nil, 0.9)
	dB := detector.NewRegex("detB", reB, nil, 0.5)
	dC := detector.NewRegex("detC", reC, nil, 0.8)
	scanner := sensitive.NewScanner(
		sensitive.WithDetector(dA),
		sensitive.WithDetector(dB),
		sensitive.WithDetector(dC),
	)
	findings := scanner.ScanString("ABCDEFGHIJKLMN")
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (A and C kept, B discarded)", len(findings))
	}
	// Both A (0.9) and C (0.8) should survive; B (0.5) bridging should be discarded.
	var hasA, hasC bool
	for _, f := range findings {
		if f.Confidence == 0.9 {
			hasA = true
		}
		if f.Confidence == 0.8 {
			hasC = true
		}
	}
	if !hasA || !hasC {
		t.Errorf("expected findings with confidence 0.9 and 0.8, got %+v", findings)
	}
}

func TestScanner_DedupSameStart(t *testing.T) {
	t.Parallel()

	// Two detectors matching the exact same range but different confidence.
	reA := regexp.MustCompile(`ABCDEF`)
	reB := regexp.MustCompile(`ABCDEF`)
	dA := detector.NewRegex("detA", reA, nil, 0.3)
	dB := detector.NewRegex("detB", reB, nil, 0.8)
	scanner := sensitive.NewScanner(
		sensitive.WithDetector(dA),
		sensitive.WithDetector(dB),
	)
	findings := scanner.ScanString("ABCDEF")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 after dedup", len(findings))
	}
	if findings[0].Confidence != 0.8 {
		t.Errorf("Confidence = %f, want 0.8", findings[0].Confidence)
	}
}

func TestScanner_WithoutDedup(t *testing.T) {
	t.Parallel()

	// Two detectors matching the exact same range — without dedup both should appear.
	reA := regexp.MustCompile(`ABCDEF`)
	reB := regexp.MustCompile(`ABCDEF`)
	dA := detector.NewRegex("detA", reA, nil, 0.3)
	dB := detector.NewRegex("detB", reB, nil, 0.8)
	scanner := sensitive.NewScanner(
		sensitive.WithDetector(dA),
		sensitive.WithDetector(dB),
		sensitive.WithoutDedup(),
	)
	findings := scanner.ScanString("ABCDEF")
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (dedup disabled)", len(findings))
	}
}

func TestScanner_ResultsSortedByConfidence(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())
	findings := scanner.ScanString("card 4532015112830366 email tanaka@example.com")
	for i := 1; i < len(findings); i++ {
		if findings[i].Confidence > findings[i-1].Confidence {
			t.Errorf("findings not sorted: [%d].Confidence=%f > [%d].Confidence=%f",
				i, findings[i].Confidence, i-1, findings[i-1].Confidence)
		}
	}
}

func TestScanner_DeterministicSortOrder(t *testing.T) {
	t.Parallel()

	// Two detectors matching non-overlapping regions with the same confidence.
	// The sort should be deterministic: tie-broken by Start, then DetectorName.
	reA := regexp.MustCompile(`AAA`)
	reB := regexp.MustCompile(`BBB`)
	dA := detector.NewRegex("detA", reA, nil, 0.7)
	dB := detector.NewRegex("detB", reB, nil, 0.7)
	scanner := sensitive.NewScanner(
		sensitive.WithDetector(dA),
		sensitive.WithDetector(dB),
		sensitive.WithoutDedup(),
	)

	// Run multiple times to verify determinism.
	for i := range 10 {
		findings := scanner.ScanString("AAA BBB")
		if len(findings) != 2 {
			t.Fatalf("got %d findings, want 2", len(findings))
		}
		// Same confidence → sorted by Start ascending → "detA" (pos 0) first.
		if findings[0].DetectorName != "detA" {
			t.Errorf("iteration %d: first finding = %s, want detA (lower Start wins tie)", i, findings[0].DetectorName)
		}
		if findings[1].DetectorName != "detB" {
			t.Errorf("iteration %d: second finding = %s, want detB", i, findings[1].DetectorName)
		}
	}
}

func TestScanner_WithSortByPosition(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(
		sensitive.WithPAN(), sensitive.WithEmail(),
		sensitive.WithSortByPosition(),
	)
	input := "card 4532015112830366 email tanaka@example.com"
	findings := scanner.ScanString(input)
	if len(findings) < 2 {
		t.Fatalf("got %d findings, want >= 2", len(findings))
	}
	// With sort-by-position, findings should be in ascending Start order.
	for i := 1; i < len(findings); i++ {
		if findings[i].Start < findings[i-1].Start {
			t.Errorf("findings not sorted by position: [%d].Start=%d < [%d].Start=%d",
				i, findings[i].Start, i-1, findings[i-1].Start)
		}
	}
	// PAN starts at offset 5, email starts at offset 21 — PAN should come first.
	if findings[0].DetectorName != detector.NamePAN {
		t.Errorf("first finding = %s, want PAN (position-ordered)", findings[0].DetectorName)
	}
}

func TestScanner_IBANPreviouslyMissedCountry(t *testing.T) {
	t.Parallel()

	// Albania (AL) was not in the old Hints() list.
	// Verify the Scanner (with hint filtering) detects it.
	scanner := sensitive.NewScanner(sensitive.WithIBAN())
	findings := scanner.ScanString("AL42000000000000000000000000")
	ibanFindings := filterByDetector(findings, detector.NameIBAN)
	if len(ibanFindings) != 1 {
		t.Fatalf("want 1 IBAN finding for Albanian IBAN, got %d", len(ibanFindings))
	}
}

func TestScanner_ScanAndMask_Integration(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail(), sensitive.WithJPPhone())
	input := "card 4532015112830366 email tanaka@example.com phone 090-1234-5678"
	findings := scanner.ScanString(input)

	strategyMap := map[sensitive.DetectorName]mask.Strategy{
		detector.NamePAN:     mask.Last4,
		detector.NameEmail:   mask.Partial,
		detector.NameJPPhone: mask.Redact,
	}
	got := mask.Mask(input, findings, strategyMap)

	// PAN should be last4 masked.
	if got == input {
		t.Error("Mask() returned unmodified input")
	}
	// The original PAN should not appear in the masked output.
	if strings.Contains(got, "4532015112830366") {
		t.Error("masked output still contains original PAN")
	}
	// The original phone should not appear in the masked output.
	if strings.Contains(got, "090-1234-5678") {
		t.Error("masked output still contains original phone")
	}
}

func TestScanner_ScanAndMaskAll_Integration(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())
	// #nosec G101 -- test key for detection behavior
	input := "key: AKIAIOSFODNN7EXAMPLE iban: DE89370400440532013000"
	findings := scanner.ScanString(input)

	got := mask.MaskAll(input, findings, mask.Redact)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("masked output still contains AWS key")
	}
	if strings.Contains(got, "DE89370400440532013000") {
		t.Error("masked output still contains IBAN")
	}
}

func TestScanner_Integration_AllDetectorTypes(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())
	tests := []struct {
		name     string
		input    string
		wantName sensitive.DetectorName
		wantMin  int
	}{
		// PAN variants
		{"Visa", "4532015112830366", detector.NamePAN, 1},
		{"Visa with dashes", "4532-0151-1283-0366", detector.NamePAN, 1},
		{"Mastercard", "5425233430109903", detector.NamePAN, 1},
		{"Mastercard 2-series", "2221000000000009", detector.NamePAN, 1},
		{"Amex", "374245455400126", detector.NamePAN, 1},
		{"JCB", "3566002020360505", detector.NamePAN, 1},
		{"Discover 6011", "6011000400000000", detector.NamePAN, 1},
		{"Discover 65", "6500000000000002", detector.NamePAN, 1},
		{"UnionPay", "6200000000000005", detector.NamePAN, 1},
		{"Diners 36", "36000000000008", detector.NamePAN, 1},
		{"Visa 13-digit", "4222222222225", detector.NamePAN, 1},
		// Email
		{"Email", "tanaka@example.com", detector.NameEmail, 1},
		// JP Phone
		{"Mobile", "090-1234-5678", detector.NameJPPhone, 1},
		{"Landline Tokyo", "03-1234-5678", detector.NameJPPhone, 1},
		{"IP Phone", "050-1234-5678", detector.NameJPPhone, 1},
		{"Toll-free 0120", "0120-123-456", detector.NameJPPhone, 1},
		{"Landline Osaka", "06-1234-5678", detector.NameJPPhone, 1},
		// My Number
		{"MyNumber", "123456789018", detector.NameMyNumber, 1},
		// JWT
		{"JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", detector.NameJWT, 1},
		// AWS Key
		{"AWSKey", "AKIAIOSFODNN7EXAMPLE", detector.NameAWSKey, 1},
		// IBAN
		{"IBAN DE", "DE89370400440532013000", detector.NameIBAN, 1},
		{"IBAN GB", "GB29NWBK60161331926819", detector.NameIBAN, 1},
		// IP Address
		{"IPv4", "192.168.1.1", detector.NameIPAddr, 1},
		{"IPv6 loopback", "::1", detector.NameIPAddr, 1},
		{"IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", detector.NameIPAddr, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := scanner.ScanString(tt.input)
			matched := filterByDetector(findings, tt.wantName)
			if len(matched) < tt.wantMin {
				t.Errorf("want >= %d %s findings, got %d (all findings: %+v)",
					tt.wantMin, tt.wantName, len(matched), findings)
			}
		})
	}
}

func TestScanner_Integration_FalsePositives(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())
	tests := []struct {
		name  string
		input string
	}{
		{"version number not IP", "v1.2.3"},
		{"short digits not PAN", "12345"},
		{"invalid Luhn unknown brand", "9000000000000001"},
		{"not a phone", "hello world"},
		{"not an IBAN", "XX1234567890"},
		{"not a JWT", "abc.def"},
		{"not AWS key", "BKIAIOSFODNN7EXAMPLE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := scanner.ScanString(tt.input)
			for _, f := range findings {
				if f.Confidence >= 0.8 {
					t.Errorf("unexpected high-confidence finding %q (confidence=%f, detector=%s)",
						f.RawValue, f.Confidence, f.DetectorName)
				}
			}
		})
	}
}

func TestScanner_Integration_MaskAllStrategies(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithPAN())
	input := "card: 4532015112830366"
	findings := scanner.ScanString(input)
	if len(findings) == 0 {
		t.Fatal("expected PAN finding")
	}

	strategies := []mask.Strategy{mask.Redact, mask.Last4, mask.First1Last4, mask.Partial, mask.Hash}
	for _, s := range strategies {
		got := mask.MaskAll(input, findings, s)
		if s != mask.Hash && len(got) != len(input) {
			t.Errorf("strategy %v: output length = %d, want %d", s, len(got), len(input))
		}
		if s == mask.Redact && strings.Contains(got, "4532015112830366") {
			t.Errorf("Redact strategy did not mask PAN")
		}
	}
}

// assertScannerDetail scans input and verifies that at least one finding
// passes the given check function.
func assertScannerDetail(t *testing.T, scanner *sensitive.Scanner, input string, check func(sensitive.Finding) bool) {
	t.Helper()
	findings := scanner.ScanString(input)
	for _, f := range findings {
		if check(f) {
			return
		}
	}
	t.Errorf("no finding passed check for input %q", input)
}

func TestScanner_Integration_FindingDetail(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())

	assertScannerDetail(t, scanner, "4532015112830366", func(f sensitive.Finding) bool {
		detail, ok := f.PANDetail()
		return ok && detail.Brand == detector.BrandVisa
	})
	assertScannerDetail(t, scanner, "090-1234-5678", func(f sensitive.Finding) bool {
		detail, ok := f.JPPhoneDetail()
		return ok && detail.PhoneType == "mobile"
	})
	assertScannerDetail(t, scanner, "123456789018", func(f sensitive.Finding) bool {
		if f.DetectorName != detector.NameMyNumber {
			return false
		}
		detail, ok := f.MyNumberDetail()
		return ok && detail.CheckDigitValid
	})
	assertScannerDetail(t, scanner, "DE89370400440532013000", func(f sensitive.Finding) bool {
		detail, ok := f.IBANDetail()
		return ok && detail.CountryCode == "DE"
	})
	assertScannerDetail(t, scanner, "192.168.1.1", func(f sensitive.Finding) bool {
		detail, ok := f.IPAddrDetail()
		return ok && detail.Version == 4
	})
}

func TestScanner_UKSortCode_SpaceSeparatedDetectedViaHint(t *testing.T) {
	t.Parallel()

	// Regression: space-separated sort codes were silently missed because
	// the hint filter only contained "-". The Scanner must detect "12 34 56"
	// even though it contains no hyphen.
	scanner := sensitive.NewScanner(sensitive.WithUKSortCode())
	findings := scanner.ScanString("sort code: 12 34 56")
	matched := filterByDetector(findings, detector.NameUKSortCode)
	if len(matched) != 1 {
		t.Fatalf("want 1 UKSortCode finding for space-separated sort code, got %d", len(matched))
	}
	if matched[0].RawValue != "12 34 56" {
		t.Errorf("RawValue = %q, want %q", matched[0].RawValue, "12 34 56")
	}
}

func TestScanner_BankAccount_AcctNoDetectedViaHint(t *testing.T) {
	t.Parallel()

	// Regression: "Acct No" and "Account No" (title case) were missing from
	// the hint list, causing Scanner to skip the bank account detector when
	// only those keyword variants appeared.
	scanner := sensitive.NewScanner(sensitive.WithBankAccount())

	tests := []struct {
		name  string
		input string
	}{
		{"Acct No title case", "Acct No 12345678"},
		{"Account No title case", "Account No 12345678"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := scanner.ScanString(tt.input)
			matched := filterByDetector(findings, detector.NameBankAccount)
			if len(matched) != 1 {
				t.Fatalf("want 1 BankAccount finding for %q, got %d", tt.input, len(matched))
			}
		})
	}
}

func TestScanner_PAN_FullWidthDetectedViaHint(t *testing.T) {
	t.Parallel()

	// Regression: full-width-only PANs were silently missed because
	// the hint filter only contained ASCII digits. The Scanner must detect
	// full-width PANs via the full-width digit hints.
	scanner := sensitive.NewScanner(sensitive.WithPAN())

	// Full-width Visa test number: ４５３２０１５１１２８３０３６６
	findings := scanner.ScanString("card is \xef\xbc\x94\xef\xbc\x95\xef\xbc\x93\xef\xbc\x92\xef\xbc\x90\xef\xbc\x91\xef\xbc\x95\xef\xbc\x91\xef\xbc\x91\xef\xbc\x92\xef\xbc\x98\xef\xbc\x93\xef\xbc\x90\xef\xbc\x93\xef\xbc\x96\xef\xbc\x96")
	panFindings := filterByDetector(findings, detector.NamePAN)
	if len(panFindings) != 1 {
		t.Fatalf("want 1 PAN finding for full-width PAN, got %d", len(panFindings))
	}
}

func TestScanner_JPPhone_FullWidthDetectedViaHint(t *testing.T) {
	t.Parallel()

	// Regression: full-width-only phone numbers were silently missed because
	// the hint filter only contained ASCII "0". The Scanner must detect
	// full-width phone numbers via the full-width zero hint (U+FF10).
	scanner := sensitive.NewScanner(sensitive.WithJPPhone())

	// Full-width: ０９０－１２３４－５６７８
	findings := scanner.ScanString("\xef\xbc\x90\xef\xbc\x99\xef\xbc\x90\xef\xbc\x8d\xef\xbc\x91\xef\xbc\x92\xef\xbc\x93\xef\xbc\x94\xef\xbc\x8d\xef\xbc\x95\xef\xbc\x96\xef\xbc\x97\xef\xbc\x98")
	jpFindings := filterByDetector(findings, detector.NameJPPhone)
	if len(jpFindings) != 1 {
		t.Fatalf("want 1 JPPhone finding for full-width phone, got %d", len(jpFindings))
	}
}

func TestScanner_DedupDeterministic(t *testing.T) {
	t.Parallel()

	// Regression: dedup sort had insufficient tiebreakers, making
	// the result non-deterministic when confidence and start matched.
	// This test runs multiple iterations to verify stability.
	scanner := sensitive.NewScanner(sensitive.WithAll())
	input := "card 4532015112830366 email tanaka@example.com"

	var prev []sensitive.Finding
	for range 20 {
		findings := scanner.ScanString(input)
		if prev != nil {
			if len(findings) != len(prev) {
				t.Fatal("non-deterministic finding count across iterations")
			}
			for i := range findings {
				if findings[i].DetectorName != prev[i].DetectorName ||
					findings[i].Start != prev[i].Start ||
					findings[i].End != prev[i].End {
					t.Fatalf("non-deterministic dedup at index %d: %+v vs %+v",
						i, findings[i], prev[i])
				}
			}
		}
		prev = findings
	}
}

func TestNewScanner_WithAllPlusIndividualDeduplicatesDetectors(t *testing.T) {
	t.Parallel()

	// Combining WithAll() and individual With*() options should not
	// register the same detector twice. Without dedup, duplicate
	// detectors would produce duplicate findings.
	scanner := sensitive.NewScanner(
		sensitive.WithAll(),
		sensitive.WithPAN(),
		sensitive.WithEmail(),
		sensitive.WithoutDedup(),
	)
	findings := scanner.ScanString("card 4532015112830366 email tanaka@example.com")

	panFindings := filterByDetector(findings, detector.NamePAN)
	if len(panFindings) != 1 {
		t.Errorf("want 1 PAN finding (deduped detectors), got %d", len(panFindings))
	}

	emailFindings := filterByDetector(findings, detector.NameEmail)
	if len(emailFindings) != 1 {
		t.Errorf("want 1 email finding (deduped detectors), got %d", len(emailFindings))
	}
}

func TestScanner_CVV_SecurityCodeAllCaps(t *testing.T) {
	t.Parallel()

	// Regression: "SECURITY CODE" was in cvvKeywords but not explicitly in
	// Hints(). The hint filter's case-insensitive matching covers it via the
	// lowercase "security code" hint. This test ensures the full Scanner
	// pipeline detects CVVs with all-caps "SECURITY CODE".
	scanner := sensitive.NewScanner(sensitive.WithCVV())
	findings := scanner.ScanString("SECURITY CODE: 789")
	matched := filterByDetector(findings, detector.NameCVV)
	if len(matched) != 1 {
		t.Fatalf("want 1 CVV finding for SECURITY CODE, got %d", len(matched))
	}
	if matched[0].RawValue != "789" {
		t.Errorf("RawValue = %q, want %q", matched[0].RawValue, "789")
	}
}

func TestScanner_IPv6_TrailingAlphaRejected(t *testing.T) {
	t.Parallel()

	// IPv6 addresses followed by non-hex alphanumeric characters should not
	// be detected because the candidate is part of a longer token.
	scanner := sensitive.NewScanner(sensitive.WithIPAddr())

	tests := []struct {
		name  string
		input string
	}{
		{"trailing letter g", "2001:db8::1g"},
		{"trailing letter xyz", "fe80::1xyz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := scanner.ScanString(tt.input)
			ipFindings := filterByDetector(findings, detector.NameIPAddr)
			if len(ipFindings) != 0 {
				t.Errorf("want 0 IPv6 findings for %q (trailing alpha), got %d: %+v",
					tt.input, len(ipFindings), ipFindings)
			}
		})
	}
}

func TestScanner_WithMinConfidence(t *testing.T) {
	t.Parallel()

	// Use BankAccount (confidence 0.5-0.65) and PAN (confidence ~1.0)
	// to test threshold filtering.
	input := "bank account 12345678 card 4532015112830366"

	t.Run("threshold 0 returns all findings", func(t *testing.T) {
		t.Parallel()
		scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithBankAccount())
		findings := scanner.ScanString(input)
		if len(findings) == 0 {
			t.Fatal("expected findings, got none")
		}
	})

	t.Run("threshold 0.8 filters low-confidence findings", func(t *testing.T) {
		t.Parallel()
		scanner := sensitive.NewScanner(
			sensitive.WithPAN(), sensitive.WithBankAccount(),
			sensitive.WithMinConfidence(0.8),
		)
		findings := scanner.ScanString(input)
		for _, f := range findings {
			if f.Confidence < 0.8 {
				t.Errorf("finding %q has confidence %.2f, want >= 0.8",
					f.DetectorName, f.Confidence)
			}
		}
		// PAN should still be present.
		panFindings := filterByDetector(findings, detector.NamePAN)
		if len(panFindings) == 0 {
			t.Error("expected PAN finding with threshold 0.8")
		}
	})

	t.Run("threshold 1.0 filters low-confidence findings", func(t *testing.T) {
		t.Parallel()
		scanner := sensitive.NewScanner(
			sensitive.WithPAN(), sensitive.WithBankAccount(),
			sensitive.WithMinConfidence(1.0),
		)
		findings := scanner.ScanString(input)
		for _, f := range findings {
			if f.Confidence < 1.0 {
				t.Errorf("finding %q has confidence %.2f, want >= 1.0",
					f.DetectorName, f.Confidence)
			}
		}
		// BankAccount (confidence 0.5-0.65) should be filtered out.
		bankFindings := filterByDetector(findings, detector.NameBankAccount)
		if len(bankFindings) != 0 {
			t.Errorf("expected 0 BankAccount findings with threshold 1.0, got %d", len(bankFindings))
		}
	})

	t.Run("threshold equals confidence includes the finding", func(t *testing.T) {
		t.Parallel()
		// Regex detector with confidence exactly 0.6.
		d := detector.NewRegex("exact", regexp.MustCompile(`EXACT`), nil, 0.6)
		scanner := sensitive.NewScanner(
			sensitive.WithDetector(d),
			sensitive.WithMinConfidence(0.6),
		)
		findings := scanner.ScanString("EXACT")
		if len(findings) != 1 {
			t.Fatalf("finding with confidence == threshold should be included, got %d findings", len(findings))
		}
	})

	t.Run("threshold just above confidence excludes the finding", func(t *testing.T) {
		t.Parallel()
		d := detector.NewRegex("exact", regexp.MustCompile(`EXACT`), nil, 0.6)
		scanner := sensitive.NewScanner(
			sensitive.WithDetector(d),
			sensitive.WithMinConfidence(0.61),
		)
		findings := scanner.ScanString("EXACT")
		if len(findings) != 0 {
			t.Fatalf("finding with confidence < threshold should be excluded, got %d findings", len(findings))
		}
	})

	t.Run("value above 1 is clamped to 1", func(t *testing.T) {
		t.Parallel()
		// 1.01 is clamped to 1.0, so PAN (confidence 1.0) should still pass.
		scanner := sensitive.NewScanner(
			sensitive.WithPAN(),
			sensitive.WithMinConfidence(1.01),
		)
		findings := scanner.ScanString("4532015112830366")
		panFindings := filterByDetector(findings, detector.NamePAN)
		if len(panFindings) == 0 {
			t.Error("expected PAN finding with clamped threshold 1.01 -> 1.0")
		}
	})
}

func filterByDetector(findings []sensitive.Finding, name sensitive.DetectorName) []sensitive.Finding {
	var filtered []sensitive.Finding
	for _, f := range findings {
		if f.DetectorName == name {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
