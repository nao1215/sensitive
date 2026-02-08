package sensitive_test

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nao1215/sensitive"
	"github.com/nao1215/sensitive/detector"
	"github.com/nao1215/sensitive/mask"
)

func ExampleNewScanner() {
	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
	findings := scanner.ScanString("user tanaka@example.com paid with 4532015112830366")

	for _, f := range findings {
		fmt.Printf("type=%s raw=%s confidence=%.2f\n", f.DetectorName, f.RawValue, f.Confidence)
	}
	// Unordered output:
	// type=pan raw=4532015112830366 confidence=1.00
	// type=email raw=tanaka@example.com confidence=1.00
}

func ExampleNewScanner_withAll() {
	scanner := sensitive.NewScanner(sensitive.WithAll())
	findings := scanner.ScanString("key: AKIAIOSFODNN7EXAMPLE")

	for _, f := range findings {
		fmt.Printf("type=%s raw=%s confidence=%.2f\n", f.DetectorName, f.RawValue, f.Confidence)
	}
	// Output:
	// type=awskey raw=AKIAIOSFODNN7EXAMPLE confidence=0.95
}

func ExampleScanner_Scan() {
	scanner := sensitive.NewScanner(sensitive.WithPAN())
	data := []byte("payment for card 4532-0151-1283-0366 amount $99.99")
	findings := scanner.Scan(data)

	for _, f := range findings {
		fmt.Printf("found %s at position [%d:%d]\n", f.DetectorName, f.Start, f.End)
	}
	// Output:
	// found pan at position [17:36]
}

func ExampleScanner_ScanString() {
	scanner := sensitive.NewScanner(sensitive.WithEmail())
	findings := scanner.ScanString("contact admin@example.com for support")

	fmt.Printf("found %d email(s)\n", len(findings))
	if len(findings) > 0 {
		fmt.Printf("email: %s\n", findings[0].RawValue)
	}
	// Output:
	// found 1 email(s)
	// email: admin@example.com
}

func ExampleWithDetector() {
	// Register a custom detector for internal project IDs.
	projectID := detector.NewRegex(
		detector.DetectorName("project_id"),
		regexp.MustCompile(`PROJ-\d{6}`),
		[][]byte{[]byte("PROJ-")},
		0.8,
	)

	scanner := sensitive.NewScanner(sensitive.WithDetector(projectID))
	findings := scanner.ScanString("assigned to PROJ-123456")

	for _, f := range findings {
		fmt.Printf("type=%s raw=%s\n", f.DetectorName, f.RawValue)
	}
	// Output:
	// type=project_id raw=PROJ-123456
}

func ExampleWithAll() {
	scanner := sensitive.NewScanner(sensitive.WithAll())
	text := "user tanaka@example.com paid with 4532015112830366 from 192.168.1.1"
	findings := scanner.ScanString(text)

	fmt.Printf("found %d sensitive item(s)\n", len(findings))
	// Output:
	// found 3 sensitive item(s)
}

func ExampleScanner_ScanReader() {
	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
	r := strings.NewReader("user tanaka@example.com paid with 4532015112830366")

	findings, err := scanner.ScanReader(r)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	for _, f := range findings {
		fmt.Printf("type=%s raw=%s\n", f.DetectorName, f.RawValue)
	}
	// Unordered output:
	// type=pan raw=4532015112830366
	// type=email raw=tanaka@example.com
}

func ExampleScanner_ScanLines() {
	scanner := sensitive.NewScanner(sensitive.WithEmail())
	input := "normal log line\nuser tanaka@example.com logged in\nanother safe line\n"

	err := scanner.ScanLines(strings.NewReader(input), func(lineNum int, _ []byte, findings []sensitive.Finding) {
		for _, f := range findings {
			fmt.Printf("line %d: %s=%s\n", lineNum, f.DetectorName, f.RawValue)
		}
	})
	if err != nil {
		fmt.Println("error:", err)
	}
	// Output:
	// line 2: email=tanaka@example.com
}

func ExampleWithMinConfidence() {
	// WithMinConfidence filters out findings below the threshold.
	// BankAccount detections have lower confidence (0.50-0.65),
	// while Email detections have high confidence (1.00).
	scanner := sensitive.NewScanner(
		sensitive.WithEmail(),
		sensitive.WithBankAccount(),
		sensitive.WithMinConfidence(0.8),
	)
	findings := scanner.ScanString("user tanaka@example.com bank account 12345678")

	for _, f := range findings {
		fmt.Printf("type=%s confidence=%.2f\n", f.DetectorName, f.Confidence)
	}
	// Output:
	// type=email confidence=1.00
}

func ExampleFinding_Kind() {
	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail(), sensitive.WithAWSKey())
	findings := scanner.ScanString("user tanaka@example.com paid with 4532015112830366 key AKIAIOSFODNN7EXAMPLE")

	for _, f := range findings {
		fmt.Printf("%s: %s\n", f.DetectorName, f.Kind())
	}
	// Unordered output:
	// pan: financial
	// email: pii
	// awskey: credential
}

// This example demonstrates how to use the mask package with the scanner
// to detect and mask sensitive data in a single pipeline.
func Example_maskingPipeline() {
	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
	text := "user tanaka@example.com paid with 4532015112830366"
	findings := scanner.ScanString(text)

	masked := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{
		detector.NamePAN:   mask.Last4,
		detector.NameEmail: mask.Partial,
	})

	fmt.Println(masked)
	// Output:
	// user t*****@example.com paid with ************0366
}
