package detect

import (
	"bytes"
	"reflect"
	"testing"
)

const (
	samplePAN      = "4242424242424242"
	sampleMyNumber = "123456789018"
	sampleMobile   = "090-1234-5678"
	sampleLandline = "03-1234-5678"
	sampleSortCode = "12-34-56"
	sampleBase58   = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	sampleBech32   = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	// #nosec G101 -- AWS publishes this example access key; it is not an authentication credential.
	sampleAccessKey  = "AKIAIOSFODNN7EXAMPLE"
	sampleIBAN       = "GB82WEST12345698765432"
	loopbackIPv4     = "127.0.0.1"
	loopbackIPv6     = "::1"
	emptyInputCase   = "empty input"
	sampleMerchantID = "ABCDE12345FGHI6"
	noKeywordCase    = "no keyword"
)

func detectorSpanFixtures() []struct {
	detector Detector
	text     string
} {
	return []struct {
		detector Detector
		text     string
	}{
		{NewPAN(), samplePAN}, {NewEmail(), "alice@example.com"}, {NewJPPhone(), sampleMobile}, {NewMyNumber(), sampleMyNumber}, {NewAWSKey(), sampleAccessKey}, {NewIBAN(), sampleIBAN}, {NewIPAddr(), "203.0.113.9"}, {NewABARouting(), "021000021"}, {NewBTC(), sampleBase58}, {&Credential{}, "password=opaqueFixture"},
	}
}

func TestFindingDetectorName(t *testing.T) {
	t.Parallel()
	for _, tc := range detectorSpanFixtures() {
		for _, f := range tc.detector.Scan([]byte(tc.text)) {
			if f.DetectorName != tc.detector.Name() {
				t.Fatal(f)
			}
		}
	}
}

func TestFindingOriginalByteOffsets(t *testing.T) {
	t.Parallel()
	for _, tc := range detectorSpanFixtures() {
		plain := tc.detector.Scan([]byte(tc.text))
		if len(plain) != 1 {
			t.Fatal(tc.text, plain)
		}
		prefix := "日本語 "
		got := tc.detector.Scan([]byte(prefix + tc.text + " "))
		if len(got) != 1 || got[0].Start != plain[0].Start+len(prefix) || got[0].End != plain[0].End+len(prefix) {
			t.Fatal(tc.text, got)
		}
	}
}

func TestDetectorInputUnmodified(t *testing.T) {
	t.Parallel()
	for _, tc := range detectorSpanFixtures() {
		input := []byte(tc.text)
		before := bytes.Clone(input)
		tc.detector.Scan(input)
		if !bytes.Equal(input, before) {
			t.Fatal(tc.detector.Name())
		}
	}
}

func TestDetectorResultsIndependentOfInput(t *testing.T) {
	t.Parallel()
	for _, tc := range detectorSpanFixtures() {
		input := []byte(tc.text)
		got := tc.detector.Scan(input)
		want := append([]Finding(nil), got...)
		clear(input)
		tc.detector.Scan(input)
		if !reflect.DeepEqual(got, want) {
			t.Fatal(tc.detector.Name(), got)
		}
	}
}

func TestFindingConfidenceRange(t *testing.T) {
	t.Parallel()
	for _, tc := range detectorSpanFixtures() {
		for _, f := range tc.detector.Scan([]byte(tc.text)) {
			if !(f.Confidence >= 0 && f.Confidence <= 1) {
				t.Fatal(f)
			}
		}
	}
}

func TestDetectorEmptyInput(t *testing.T) {
	t.Parallel()
	for _, tc := range detectorSpanFixtures() {
		if got := tc.detector.Scan(nil); len(got) != 0 {
			t.Fatal(tc.detector.Name(), got)
		}
	}
}

// testDigits extracts normalized digits for direct checksum and issuer oracles.
func testDigits(data []byte) []byte {
	data, _ = normalizeDigits(data)
	var digits []byte
	for _, b := range data {
		if b >= '0' && b <= '9' {
			digits = append(digits, b)
		}
	}
	return digits
}

func assertDetectorScan(t *testing.T, d Detector, input string, count int, matched string, confidence float64) {
	t.Helper()
	findings := d.Scan([]byte(input))
	if len(findings) != count {
		t.Fatalf("got %d findings, want %d: %+v", len(findings), count, findings)
	}
	for _, f := range findings {
		if f.Start < 0 || f.End > len(input) || f.Start >= f.End {
			t.Fatalf("invalid span: %+v", f)
		}
	}
	if count == 0 {
		return
	}
	if matched != "" && input[findings[0].Start:findings[0].End] != matched {
		t.Errorf("matched text = %q, want %q", input[findings[0].Start:findings[0].End], matched)
	}
	if confidence > 0 && findings[0].Confidence < confidence {
		t.Errorf("Confidence = %f, want >= %f", findings[0].Confidence, confidence)
	}
}

// assertScanCase checks a table case: the finding count, the first match when
// matched is set, and that every finding reaches the minimum confidence.
func assertScanCase(t *testing.T, d Detector, input string, count int, matched string, minimum float64) {
	t.Helper()
	findings := d.Scan([]byte(input))
	if len(findings) != count {
		t.Fatalf("got %d findings, want %d; findings=%+v", len(findings), count, findings)
	}
	if count == 0 {
		return
	}
	if matched != "" && input[findings[0].Start:findings[0].End] != matched {
		t.Errorf("matched text = %q, want %q", input[findings[0].Start:findings[0].End], matched)
	}
	for _, f := range findings {
		if f.Confidence < minimum {
			t.Errorf("Confidence = %f, want >= %f", f.Confidence, minimum)
		}
	}
}

// assertScanMatch checks a table case whose first finding, when any, must
// cover exactly matched, including an empty matched text.
func assertScanMatch(t *testing.T, d Detector, input string, count int, matched string) {
	t.Helper()
	findings := d.Scan([]byte(input))
	if len(findings) != count {
		t.Fatalf("got %d findings, want %d: %+v", len(findings), count, findings)
	}
	if count > 0 && input[findings[0].Start:findings[0].End] != matched {
		t.Errorf("matched text = %q, want %q", input[findings[0].Start:findings[0].End], matched)
	}
}

func TestReadsLabel(t *testing.T) {
	t.Parallel()
	free := []Detector{NewIBAN(), &BTC{}, &ETH{}, &Email{}, &JWT{}, NewAWSKey(), &GitHubToken{}, &SlackToken{}, &GoogleAPIKey{}, &PrivateKeyPEM{}, &PaymentToken{}, NewServiceToken()}
	for _, d := range free {
		if ReadsLabel(d) {
			t.Errorf("%s reads labels, want the value alone", d.Name())
		}
	}
	for _, d := range []Detector{&Credential{}, &HighEntropy{}, &CVV{}, NewSWIFTBIC(), &IPAddr{}} {
		if !ReadsLabel(d) {
			t.Errorf("%s does not read labels", d.Name())
		}
	}
}
