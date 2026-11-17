package detect_test

import (
	"bytes"
	"fmt"

	"github.com/nao1215/embargo/internal/detect"
)

func ExampleNewPAN() {
	input := "card is 4532015112830366"
	for _, f := range detect.NewPAN().Scan([]byte(input)) {
		fmt.Printf("%s [%d:%d] %.2f\n", f.DetectorName, f.Start, f.End, f.Confidence)
	}
	// Output: pan [8:24] 1.00
}

func ExampleNewEmail() {
	input := "send to tanaka@example.com please"
	for _, f := range detect.NewEmail().Scan([]byte(input)) {
		fmt.Printf("%s [%d:%d] %.2f\n", f.DetectorName, f.Start, f.End, f.Confidence)
	}
	// Output: email [8:26] 1.00
}

func ExampleNewJPPhone() {
	input := "TEL: 090-1234-5678"
	for _, f := range detect.NewJPPhone().Scan([]byte(input)) {
		fmt.Printf("%s [%d:%d] %.2f\n", f.DetectorName, f.Start, f.End, f.Confidence)
	}
	// Output: phone_jp [5:18] 0.90
}

func ExampleNewMyNumber() {
	input := "mynumber: 123456789018"
	for _, f := range detect.NewMyNumber().Scan([]byte(input)) {
		fmt.Printf("%s [%d:%d] %.2f\n", f.DetectorName, f.Start, f.End, f.Confidence)
	}
	// Output: mynumber [10:22] 0.95
}

func ExampleNewAWSKey() {
	input := "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
	for _, f := range detect.NewAWSKey().Scan([]byte(input)) {
		fmt.Printf("%s [%d:%d] %.2f\n", f.DetectorName, f.Start, f.End, f.Confidence)
	}
	// Output: awskey [20:40] 0.95
}

func ExampleNewIBAN() {
	input := "IBAN: DE89370400440532013000"
	for _, f := range detect.NewIBAN().Scan([]byte(input)) {
		fmt.Printf("%s [%d:%d] %.2f\n", f.DetectorName, f.Start, f.End, f.Confidence)
	}
	// Output: iban [6:28] 0.95
}

func ExampleNewIPAddr() {
	input := "server at 192.168.1.1 responded"
	for _, f := range detect.NewIPAddr().Scan([]byte(input)) {
		fmt.Printf("%s [%d:%d] %.2f\n", f.DetectorName, f.Start, f.End, f.Confidence)
	}
	// Output: ipaddr [10:21] 0.80
}

func ExamplePAN_Scan() {
	for _, input := range []string{"4532015112830366", "4532-0151-1283-0366", "4532 0151 1283 0366"} {
		for _, f := range detect.NewPAN().Scan([]byte(input)) {
			fmt.Println(input[f.Start:f.End])
		}
	}
	// Output:
	// 4532015112830366
	// 4532-0151-1283-0366
	// 4532 0151 1283 0366
}

func ExampleNewJWT() {
	// #nosec G101 -- Synthetic unsigned JWT fixture.
	input := "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
	for _, f := range detect.NewJWT().Scan([]byte(input)) {
		fmt.Printf("%s %.2f\n", f.DetectorName, f.Confidence)
	}
	// Output: jwt 0.80
}

func ExampleNormalizeFullWidthDigits() {
	normalized, _ := detect.NormalizeFullWidthDigits([]byte("０９０－１２３４－５６７８"))
	fmt.Println(string(normalized))
	// Output: 090-1234-5678
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
			Confidence: 1,
		})
		start = end
	}
	return findings
}

func ExampleDetector() {
	custom := markerDetector{marker: []byte("INTERNAL-ONLY")}
	scanner := custom
	for _, f := range scanner.Scan([]byte("scope: INTERNAL-ONLY")) {
		fmt.Printf("%s [%d:%d]: %s\n", f.DetectorName, f.Start, f.End, "scope: INTERNAL-ONLY"[f.Start:f.End])
	}

	// Output:
	// internal_marker [7:20]: INTERNAL-ONLY
}
