package sensitive_test

import (
	"fmt"
	"regexp"

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
