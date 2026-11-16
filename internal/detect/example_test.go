package detect_test

import (
	"bytes"
	"fmt"

	"github.com/nao1215/embargo/internal/detect"
)

func ExampleNewPAN() {
	d := detect.NewPAN()
	findings := d.Scan([]byte("card is 4532015112830366"))

	for _, f := range findings {
		detail, _ := f.PANDetail()

		fmt.Printf("brand=%s bin=%s last4=%s luhn=%t confidence=%.2f\n",
			detail.Brand, detail.BIN, detail.Last4, detail.Luhn, f.Confidence)
	}

	// Output:
	// brand=Visa bin=453201 last4=0366 luhn=true confidence=1.00
}

func ExamplePAN_Scan() {
	d := detect.NewPAN()

	// Detects PANs with various separators.
	for _, input := range []string{
		"4532015112830366",
		"4532-0151-1283-0366",
		"4532 0151 1283 0366",
	} {
		findings := d.Scan([]byte(input))
		if len(findings) > 0 {
			detail, _ := findings[0].PANDetail()

			fmt.Printf("input=%q brand=%s\n", input, detail.Brand)
		}
	}

	// Output:
	// input="4532015112830366" brand=Visa
	// input="4532-0151-1283-0366" brand=Visa
	// input="4532 0151 1283 0366" brand=Visa
}

func ExampleNewEmail() {
	d := detect.NewEmail()
	findings := d.Scan([]byte("send to tanaka@example.com please"))

	for _, f := range findings {
		detail, _ := f.EmailDetail()

		fmt.Printf("local=%s domain=%s\n", detail.Local, detail.Domain)
	}

	// Output:
	// local=tanaka domain=example.com
}

func ExampleNewJPPhone() {
	d := detect.NewJPPhone()
	findings := d.Scan([]byte("TEL: 090-1234-5678"))

	for _, f := range findings {
		detail, _ := f.JPPhoneDetail()

		fmt.Printf("phone=%s type=%s\n", f.RawValue, detail.PhoneType)
	}

	// Output:
	// phone=090-1234-5678 type=mobile
}

func ExampleNewMyNumber() {
	d := detect.NewMyNumber()
	// 123456789018 is a fictitious number with a valid check digit.
	findings := d.Scan([]byte("mynumber: 123456789018"))

	for _, f := range findings {
		fmt.Printf("mynumber=%s confidence=%.2f\n", f.RawValue, f.Confidence)
	}

	// Output:
	// mynumber=123456789018 confidence=0.95
}

func ExampleNewJWT() {
	d := detect.NewJWT()
	// #nosec G101 -- test token for JWT detection
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	findings := d.Scan([]byte("Bearer " + token))

	for _, f := range findings {
		detail, _ := f.JWTDetail()

		fmt.Printf("algorithm=%s confidence=%.1f\n", detail.Algorithm, f.Confidence)
	}

	// Output:
	// algorithm=HS256 confidence=1.0
}

func ExampleNewAWSKey() {
	d := detect.NewAWSKey()
	findings := d.Scan([]byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE"))

	for _, f := range findings {
		detail, _ := f.AWSKeyDetail()

		fmt.Printf("awskey=%s type=%s\n", f.RawValue, detail.KeyType)
	}

	// Output:
	// awskey=AKIAIOSFODNN7EXAMPLE type=long_term
}

func ExampleNewIBAN() {
	d := detect.NewIBAN()
	findings := d.Scan([]byte("IBAN: DE89370400440532013000"))

	for _, f := range findings {
		detail, _ := f.IBANDetail()

		fmt.Printf("iban=%s country=%s\n", f.RawValue, detail.CountryCode)
	}

	// Output:
	// iban=DE89370400440532013000 country=DE
}

func ExampleNewIPAddr() {
	d := detect.NewIPAddr()
	findings := d.Scan([]byte("server at 192.168.1.1 responded"))

	for _, f := range findings {
		detail, _ := f.IPAddrDetail()

		fmt.Printf("ip=%s version=%d\n", f.RawValue, detail.Version)
	}

	// Output:
	// ip=192.168.1.1 version=4
}

func ExampleFinding_PANDetail() {
	finding := detect.NewPAN().Scan([]byte("4532015112830366"))[0]
	if detail, ok := finding.PANDetail(); ok {
		fmt.Printf("brand=%s last4=%s\n", detail.Brand, detail.Last4)
	}
	_, ok := finding.EmailDetail()

	fmt.Println("email detail:", ok)

	// Output:
	// brand=Visa last4=0366
	// email detail: false
}

func ExampleFinding_IsPAN() {
	d := detect.NewPAN()
	findings := d.Scan([]byte("card: 4532015112830366"))

	for _, f := range findings {
		fmt.Printf("IsPAN=%t IsEmail=%t\n", f.IsPAN(), f.IsEmail())
	}

	// Output:
	// IsPAN=true IsEmail=false
}

func ExampleFinding_Is() {
	d := detect.NewEmail()
	findings := d.Scan([]byte("user@example.com"))

	for _, f := range findings {
		fmt.Printf("Is(email)=%t Is(pan)=%t\n", f.Is(detect.NameEmail), f.Is(detect.NamePAN))
	}

	// Output:
	// Is(email)=true Is(pan)=false
}

func ExampleFinding_Level() {
	d := detect.NewPAN()
	findings := d.Scan([]byte("4532015112830366"))

	for _, f := range findings {
		fmt.Printf("level=%s confidence=%.2f\n", f.Level(), f.Confidence)
	}

	// Output:
	// level=high confidence=1.00
}

func ExampleConfidenceLevel_String() {
	fmt.Println(detect.ConfidenceHigh)

	fmt.Println(detect.ConfidenceMedium)

	fmt.Println(detect.ConfidenceLow)

	// Output:
	// high
	// medium
	// low
}

func ExampleNormalizeFullWidthDigits() {
	input := []byte("０９０－１２３４－５６７８")
	normalized, _ := detect.NormalizeFullWidthDigits(input)

	fmt.Println(string(normalized))

	// Output:
	// 090-1234-5678
}

func ExampleFinding_Kind() {
	for _, name := range []detect.DetectorName{detect.NamePAN, detect.NameEmail, detect.NameAWSKey, "custom"} {
		finding := detect.Finding{DetectorName: name}

		fmt.Printf("%s: %q\n", name, finding.Kind())
	}

	// Output:
	// pan: "financial"
	// email: "pii"
	// awskey: "credential"
	// custom: ""
}

// markerDetector finds an application's exact internal classification marker.
type markerDetector struct {
	marker []byte
}

// Name returns the name used for scanner registration and findings.
func (d markerDetector) Name() detect.DetectorName { return "internal_marker" }

// Hints returns a substring present in every match.
func (d markerDetector) Hints() [][]byte { return [][]byte{d.marker} }

// Scan returns non-overlapping marker occurrences with original byte offsets.
func (d markerDetector) Scan(data []byte) []detect.Finding {
	if len(d.marker) == 0 {
		return nil
	}
	var findings []detect.Finding
	for start := 0; start < len(data); {
		n := bytes.Index(data[start:], d.marker)
		if n < 0 {
			break
		}
		start += n
		end := start + len(d.marker)
		findings = append(findings, detect.Finding{
			DetectorName: d.Name(), Start: start, End: end,
			RawValue: string(data[start:end]), Confidence: 1,
		})
		start = end
	}
	return findings
}

func ExampleDetector() {
	custom := markerDetector{marker: []byte("INTERNAL-ONLY")}
	scanner := custom
	for _, f := range scanner.Scan([]byte("scope: INTERNAL-ONLY")) {
		fmt.Printf("%s [%d:%d]: %s\n", f.DetectorName, f.Start, f.End, f.RawValue)
	}

	// Output:
	// internal_marker [7:20]: INTERNAL-ONLY
}
