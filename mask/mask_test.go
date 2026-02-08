package mask_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nao1215/sensitive"
	"github.com/nao1215/sensitive/detector"
	"github.com/nao1215/sensitive/mask"
)

func TestMask(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		text        string
		findings    []sensitive.Finding
		strategyMap map[sensitive.DetectorName]mask.Strategy
		want        string
	}{
		{
			name: "mask PAN with Last4",
			text: "card is 4532015112830366",
			findings: []sensitive.Finding{
				{DetectorName: detector.NamePAN, Start: 8, End: 24, RawValue: "4532015112830366"},
			},
			strategyMap: map[sensitive.DetectorName]mask.Strategy{detector.NamePAN: mask.Last4},
			want:        "card is ************0366",
		},
		{
			name: "mask email with Partial",
			text: "user tanaka@example.com here",
			findings: []sensitive.Finding{
				{DetectorName: detector.NameEmail, Start: 5, End: 23, RawValue: "tanaka@example.com"},
			},
			strategyMap: map[sensitive.DetectorName]mask.Strategy{detector.NameEmail: mask.Partial},
			want:        "user t*****@example.com here",
		},
		{
			name: "mask with Redact",
			text: "secret: AKIAIOSFODNN7EXAMPLE",
			findings: []sensitive.Finding{
				{DetectorName: detector.NameAWSKey, Start: 8, End: 28, RawValue: "AKIAIOSFODNN7EXAMPLE"},
			},
			strategyMap: map[sensitive.DetectorName]mask.Strategy{detector.NameAWSKey: mask.Redact},
			want:        "secret: ********************",
		},
		{
			name:        "no findings",
			text:        "nothing to mask here",
			findings:    nil,
			strategyMap: nil,
			want:        "nothing to mask here",
		},
		{
			name: "unmapped detector left unmasked",
			text: "card is 4532015112830366",
			findings: []sensitive.Finding{
				{DetectorName: detector.NamePAN, Start: 8, End: 24, RawValue: "4532015112830366"},
			},
			strategyMap: map[sensitive.DetectorName]mask.Strategy{detector.NameEmail: mask.Redact},
			want:        "card is 4532015112830366",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := mask.Mask(tt.text, tt.findings, tt.strategyMap)
			if got != tt.want {
				t.Errorf("Mask() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMaskAll(t *testing.T) {
	t.Parallel()

	text := "card 4532015112830366 email tanaka@example.com"
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: 5, End: 21, RawValue: "4532015112830366"},
		{DetectorName: detector.NameEmail, Start: 28, End: 46, RawValue: "tanaka@example.com"},
	}

	got := mask.MaskAll(text, findings, mask.Redact)
	want := "card **************** email ******************"
	if got != want {
		t.Errorf("MaskAll() = %q, want %q", got, want)
	}
}

func TestMask_Hash(t *testing.T) {
	t.Parallel()

	// #nosec G101 -- test key for masking behavior
	text := "key: AKIAIOSFODNN7EXAMPLE"
	findings := []sensitive.Finding{
		{DetectorName: detector.NameAWSKey, Start: 5, End: 25, RawValue: "AKIAIOSFODNN7EXAMPLE"},
	}

	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NameAWSKey: mask.Hash})
	// Hash produces 8 hex chars.
	if len(got) != len("key: ")+8 {
		t.Errorf("Hash mask length = %d, want %d (got %q)", len(got), len("key: ")+8, got)
	}
}

func TestMask_First1Last4(t *testing.T) {
	t.Parallel()

	text := "card: 4532015112830366"
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: 6, End: 22, RawValue: "4532015112830366"},
	}

	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NamePAN: mask.First1Last4})
	want := "card: 4***********0366"
	if got != want {
		t.Errorf("First1Last4 Mask() = %q, want %q", got, want)
	}
}

func TestMask_Last4Short(t *testing.T) {
	t.Parallel()

	// Value with 4 or fewer chars should be returned as-is.
	text := "val: abcd"
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: 5, End: 9, RawValue: "abcd"},
	}
	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NamePAN: mask.Last4})
	if got != "val: abcd" {
		t.Errorf("Last4 short Mask() = %q, want %q", got, "val: abcd")
	}
}

func TestMask_First1Last4Short(t *testing.T) {
	t.Parallel()

	// Value with 5 or fewer chars should be returned as-is.
	text := "val: abcde"
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: 5, End: 10, RawValue: "abcde"},
	}
	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NamePAN: mask.First1Last4})
	if got != "val: abcde" {
		t.Errorf("First1Last4 short Mask() = %q, want %q", got, "val: abcde")
	}
}

func TestMask_PartialEmail(t *testing.T) {
	t.Parallel()

	// Single-char local part should be returned as-is.
	text := "email: a@example.com"
	findings := []sensitive.Finding{
		{DetectorName: detector.NameEmail, Start: 7, End: 20, RawValue: "a@example.com"},
	}
	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NameEmail: mask.Partial})
	if got != "email: a@example.com" {
		t.Errorf("Partial single-char Mask() = %q, want %q", got, "email: a@example.com")
	}
}

func TestMask_PartialNonEmail(t *testing.T) {
	t.Parallel()

	// Non-email value falls back to Last4 behavior.
	text := "phone: 09012345678"
	findings := []sensitive.Finding{
		{DetectorName: detector.NameJPPhone, Start: 7, End: 18, RawValue: "09012345678"},
	}
	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NameJPPhone: mask.Partial})
	want := "phone: *******5678"
	if got != want {
		t.Errorf("Partial non-email Mask() = %q, want %q", got, want)
	}
}

func TestMask_PartialNonEmailShort(t *testing.T) {
	t.Parallel()

	// Short non-email value (<=4 chars) should be returned as-is.
	text := "val: abc"
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: 5, End: 8, RawValue: "abc"},
	}
	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NamePAN: mask.Partial})
	if got != "val: abc" {
		t.Errorf("Partial short non-email Mask() = %q, want %q", got, "val: abc")
	}
}

func TestMask_FullWidthRuneSafety(t *testing.T) {
	t.Parallel()

	// Full-width digits: each rune is 3 bytes in UTF-8.
	// "０１２３４５６７" = 8 full-width digits (24 bytes, 8 runes).
	fullWidth := "０１２３４５６７"
	start := len("val: ")
	text := "val: " + fullWidth
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: start, End: start + len(fullWidth), RawValue: fullWidth},
	}

	tests := []struct {
		name     string
		strategy mask.Strategy
		want     string
	}{
		{
			name:     "Redact full-width produces rune-count asterisks",
			strategy: mask.Redact,
			want:     "val: ********",
		},
		{
			name:     "Last4 full-width preserves last 4 runes",
			strategy: mask.Last4,
			want:     "val: ****４５６７",
		},
		{
			name:     "First1Last4 full-width preserves first 1 and last 4 runes",
			strategy: mask.First1Last4,
			want:     "val: ０***４５６７",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NamePAN: tt.strategy})
			if got != tt.want {
				t.Errorf("Mask(%s) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestMask_UnknownStrategy(t *testing.T) {
	t.Parallel()

	text := "val: secret"
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: 5, End: 11, RawValue: "secret"},
	}
	// Strategy value 99 is not defined, should return raw value.
	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NamePAN: mask.Strategy(99)})
	if got != "val: secret" {
		t.Errorf("Unknown strategy Mask() = %q, want %q", got, "val: secret")
	}
}

func TestMask_OutOfBoundsSkipped(t *testing.T) {
	t.Parallel()

	text := "hello world"
	findings := []sensitive.Finding{
		// Start negative — should be skipped.
		{DetectorName: detector.NamePAN, Start: -1, End: 5, RawValue: "hello"},
		// End exceeds text length — should be skipped.
		{DetectorName: detector.NamePAN, Start: 0, End: 999, RawValue: "hello world"},
		// Start >= End — should be skipped.
		{DetectorName: detector.NamePAN, Start: 5, End: 5, RawValue: ""},
	}
	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NamePAN: mask.Redact})
	if got != text {
		t.Errorf("Mask() with invalid findings = %q, want %q (unchanged)", got, text)
	}
}

func TestMask_OverlappingFindingsSkipped(t *testing.T) {
	t.Parallel()

	text := "ABCDEFGHIJ"
	// Two overlapping findings: [0,6) and [4,10).
	// Processing right-to-left, [4,10) is applied first; [0,6) overlaps and is skipped.
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: 0, End: 6, RawValue: "ABCDEF"},
		{DetectorName: detector.NamePAN, Start: 4, End: 10, RawValue: "EFGHIJ"},
	}
	got := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{detector.NamePAN: mask.Redact})
	want := "ABCD******"
	if got != want {
		t.Errorf("Mask() with overlapping findings = %q, want %q", got, want)
	}
}

func TestMaskAll_NoFindings(t *testing.T) {
	t.Parallel()

	got := mask.MaskAll("hello world", nil, mask.Redact)
	if got != "hello world" {
		t.Errorf("MaskAll(nil) = %q, want %q", got, "hello world")
	}
}

func TestMask_MultipleFindings(t *testing.T) {
	t.Parallel()

	text := "card 4532015112830366 phone 090-1234-5678"
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: 5, End: 21, RawValue: "4532015112830366"},
		{DetectorName: detector.NameJPPhone, Start: 28, End: 41, RawValue: "090-1234-5678"},
	}
	strategyMap := map[sensitive.DetectorName]mask.Strategy{
		detector.NamePAN:     mask.Redact,
		detector.NameJPPhone: mask.Last4,
	}
	got := mask.Mask(text, findings, strategyMap)
	want := "card **************** phone *********5678"
	if got != want {
		t.Errorf("Multiple findings Mask() = %q, want %q", got, want)
	}
}

// Integration tests that exercise real scanner → mask pipeline.

func TestMask_Integration_ScanAndMask(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
	input := "card 4532015112830366 email tanaka@example.com"
	findings := scanner.ScanString(input)

	strategyMap := map[sensitive.DetectorName]mask.Strategy{
		detector.NamePAN:   mask.Last4,
		detector.NameEmail: mask.Partial,
	}
	got := mask.Mask(input, findings, strategyMap)

	if strings.Contains(got, "4532015112830366") {
		t.Error("masked output still contains original PAN")
	}
	if strings.Contains(got, "tanaka@example.com") {
		t.Error("masked output still contains original email")
	}
}

func TestMask_Integration_ScanAllAndRedact(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(
		sensitive.WithJPPhone(),
		sensitive.WithMyNumber(),
		sensitive.WithJWT(),
		sensitive.WithAWSKey(),
		sensitive.WithIBAN(),
		sensitive.WithIPAddr(),
	)
	input := "phone 090-1234-5678 ip 192.168.1.1 key AKIAIOSFODNN7EXAMPLE iban DE89370400440532013000"
	findings := scanner.ScanString(input)

	got := mask.MaskAll(input, findings, mask.Redact)
	if strings.Contains(got, "090-1234-5678") {
		t.Error("masked output still contains phone")
	}
	if strings.Contains(got, "192.168.1.1") {
		t.Error("masked output still contains IP")
	}
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("masked output still contains AWS key")
	}
	if strings.Contains(got, "DE89370400440532013000") {
		t.Error("masked output still contains IBAN")
	}
}

func TestMask_Integration_AllDetectorVariants(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())

	tests := []struct {
		name     string
		input    string
		strategy mask.Strategy
		mustHide string
	}{
		// PAN variants (exercise identifyBrand and isExpectedLength branches)
		{"Visa", "card: 4532015112830366", mask.Last4, "4532015112830366"},
		{"Visa dashes", "card: 4532-0151-1283-0366", mask.Last4, "4532-0151-1283-0366"},
		{"Mastercard", "card: 5425233430109903", mask.Redact, "5425233430109903"},
		{"Mastercard 2-series", "card: 2221000000000009", mask.Redact, "2221000000000009"},
		{"Amex", "card: 374245455400126", mask.First1Last4, "374245455400126"},
		{"JCB", "card: 3566002020360505", mask.Redact, "3566002020360505"},
		{"Discover", "card: 6011000400000000", mask.Redact, "6011000400000000"},
		{"UnionPay", "card: 6200000000000005", mask.Last4, "6200000000000005"},
		{"Diners", "card: 36000000000008", mask.Redact, "36000000000008"},
		// Email
		{"Email", "user: tanaka@example.com", mask.Partial, "tanaka@example.com"},
		// JP Phone variants (exercise classifyJPPhone branches)
		{"Mobile 090", "tel: 090-1234-5678", mask.Redact, "090-1234-5678"},
		{"Mobile 080", "tel: 080-1234-5678", mask.Redact, "080-1234-5678"},
		{"Mobile 070", "tel: 070-1234-5678", mask.Redact, "070-1234-5678"},
		{"IP phone 050", "tel: 050-1234-5678", mask.Redact, "050-1234-5678"},
		{"Landline 03", "tel: 03-1234-5678", mask.Redact, "03-1234-5678"},
		{"Landline 06", "tel: 06-1234-5678", mask.Redact, "06-1234-5678"},
		{"Toll-free", "tel: 0120-123-456", mask.Redact, "0120-123-456"},
		// My Number
		{"MyNumber", "num: 123456789018", mask.Hash, "123456789018"},
		// AWS Key
		{"AWSKey", "key: AKIAIOSFODNN7EXAMPLE", mask.Redact, "AKIAIOSFODNN7EXAMPLE"},
		// IBAN variants
		{"IBAN DE", "iban: DE89370400440532013000", mask.Last4, "DE89370400440532013000"},
		{"IBAN GB", "iban: GB29NWBK60161331926819", mask.Last4, "GB29NWBK60161331926819"},
		// IP Address
		{"IPv4", "host: 192.168.1.1", mask.Redact, "192.168.1.1"},
		// JWT
		{"JWT", "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", mask.Redact,
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := scanner.ScanString(tt.input)
			got := mask.MaskAll(tt.input, findings, tt.strategy)
			if strings.Contains(got, tt.mustHide) {
				t.Errorf("masked output still contains %q: got %q", tt.mustHide, got)
			}
		})
	}
}

func TestMask_Integration_FalsePositivesNoMask(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())
	inputs := []string{
		"v1.2.3",
		"hello world",
		"12345",
		"XX1234567890",
		"not sensitive data",
	}

	for _, input := range inputs {
		findings := scanner.ScanString(input)
		got := mask.MaskAll(input, findings, mask.Redact)
		// For non-sensitive input, the output should be identical to the input
		// (or at least not contain asterisks from masking).
		if got != input && strings.Contains(got, "***") {
			t.Errorf("false positive masking for %q: got %q", input, got)
		}
	}
}

// assertFindingDetail scans input and verifies that at least one finding
// passes the given check function.
func assertFindingDetail(t *testing.T, scanner *sensitive.Scanner, input string, check func(sensitive.Finding) bool) {
	t.Helper()
	findings := scanner.ScanString(input)
	for _, f := range findings {
		if check(f) {
			return
		}
	}
	t.Errorf("no finding passed check for input %q", input)
}

func TestMask_Integration_FindingDetails(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())

	assertFindingDetail(t, scanner, "4532015112830366", func(f sensitive.Finding) bool {
		detail, ok := f.PANDetail()
		return ok && detail.Brand != ""
	})
	assertFindingDetail(t, scanner, "090-1234-5678", func(f sensitive.Finding) bool {
		detail, ok := f.JPPhoneDetail()
		return ok && detail.PhoneType != ""
	})
	assertFindingDetail(t, scanner, "DE89370400440532013000", func(f sensitive.Finding) bool {
		detail, ok := f.IBANDetail()
		return ok && detail.CountryCode != ""
	})
	assertFindingDetail(t, scanner, "192.168.1.1", func(f sensitive.Finding) bool {
		detail, ok := f.IPAddrDetail()
		return ok && detail.Version != 0
	})
	assertFindingDetail(t, scanner, "123456789018", func(f sensitive.Finding) bool {
		if f.DetectorName != detector.NameMyNumber {
			return false
		}
		detail, ok := f.MyNumberDetail()
		return ok && detail.CheckDigitValid
	})
}

func TestMask_Integration_FindingHelpers_IsAndLevel(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())

	panFindings := scanner.ScanString("4532015112830366")
	if len(panFindings) > 0 {
		f := panFindings[0]
		if !f.IsPAN() {
			t.Error("IsPAN() = false, want true")
		}
		if !f.Is(detector.NamePAN) {
			t.Error("Is(NamePAN) = false, want true")
		}
		if f.IsEmail() || f.IsJPPhone() || f.IsMyNumber() || f.IsJWT() || f.IsAWSKey() || f.IsIBAN() || f.IsIPAddr() {
			t.Error("other Is* returned true for PAN finding")
		}
		level := f.Level()
		if level != detector.ConfidenceHigh {
			t.Errorf("Level() = %v, want ConfidenceHigh", level)
		}
		if level.String() != "high" {
			t.Errorf("Level().String() = %q, want %q", level.String(), "high")
		}
	}
}

func TestMask_Integration_FindingHelpers_ConfidenceLevels(t *testing.T) {
	t.Parallel()

	medF := sensitive.Finding{Confidence: 0.5}
	if medF.Level() != detector.ConfidenceMedium {
		t.Errorf("Level() for 0.5 = %v, want medium", medF.Level())
	}
	if medF.Level().String() != "medium" {
		t.Errorf("String() = %q, want medium", medF.Level().String())
	}

	lowF := sensitive.Finding{Confidence: 0.1}
	if lowF.Level() != detector.ConfidenceLow {
		t.Errorf("Level() for 0.1 = %v, want low", lowF.Level())
	}
	if lowF.Level().String() != "low" {
		t.Errorf("String() = %q, want low", lowF.Level().String())
	}

	unknown := detector.ConfidenceLevel(99)
	if unknown.String() != "unknown" {
		t.Errorf("ConfidenceLevel(99).String() = %q, want unknown", unknown.String())
	}
}

func TestMask_Integration_FindingHelpers_DetailAccessors(t *testing.T) {
	t.Parallel()

	scanner := sensitive.NewScanner(sensitive.WithAll())

	assertFindingDetail(t, scanner, "tanaka@example.com", func(f sensitive.Finding) bool {
		if !f.IsEmail() {
			return false
		}
		_, ok := f.EmailDetail()
		return ok
	})
	assertFindingDetail(t, scanner, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", func(f sensitive.Finding) bool {
		if !f.IsJWT() {
			return false
		}
		_, ok := f.JWTDetail()
		return ok
	})
	assertFindingDetail(t, scanner, "AKIAIOSFODNN7EXAMPLE", func(f sensitive.Finding) bool {
		if !f.IsAWSKey() {
			return false
		}
		_, ok := f.AWSKeyDetail()
		return ok
	})
}

func TestMask_Integration_WithRegexDetector(t *testing.T) {
	t.Parallel()

	re := regexp.MustCompile(`SECRET-\d{6}`)
	d := detector.NewRegex("secret_id", re, [][]byte{[]byte("SECRET-")}, 0.8)
	scanner := sensitive.NewScanner(sensitive.WithDetector(d))

	input := "the code is SECRET-123456 here"
	findings := scanner.ScanString(input)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	got := mask.MaskAll(input, findings, mask.Redact)
	if strings.Contains(got, "SECRET-123456") {
		t.Error("masked output still contains SECRET-123456")
	}
}
