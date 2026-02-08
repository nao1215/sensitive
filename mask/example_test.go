package mask_test

import (
	"fmt"

	"github.com/nao1215/sensitive"
	"github.com/nao1215/sensitive/detector"
	"github.com/nao1215/sensitive/mask"
)

func ExampleMask() {
	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
	text := "user tanaka@example.com paid with 4532015112830366"
	findings := scanner.ScanString(text)

	// Apply different masking strategies per detector.
	masked := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{
		detector.NamePAN:   mask.Last4,
		detector.NameEmail: mask.Partial,
	})

	fmt.Println(masked)
	// Output:
	// user t*****@example.com paid with ************0366
}

func ExampleMask_redact() {
	// #nosec G101 -- test key for masking behavior
	text := "key: AKIAIOSFODNN7EXAMPLE"
	findings := []sensitive.Finding{
		{DetectorName: detector.NameAWSKey, Start: 5, End: 25, RawValue: "AKIAIOSFODNN7EXAMPLE"},
	}

	masked := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{
		detector.NameAWSKey: mask.Redact,
	})

	fmt.Println(masked)
	// Output:
	// key: ********************
}

func ExampleMask_first1Last4() {
	text := "card: 4532015112830366"
	findings := []sensitive.Finding{
		{DetectorName: detector.NamePAN, Start: 6, End: 22, RawValue: "4532015112830366"},
	}

	masked := mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{
		detector.NamePAN: mask.First1Last4,
	})

	fmt.Println(masked)
	// Output:
	// card: 4***********0366
}

func ExampleMaskAll() {
	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
	text := "user tanaka@example.com paid with 4532015112830366"
	findings := scanner.ScanString(text)

	// Apply the same strategy to all findings.
	masked := mask.MaskAll(text, findings, mask.Redact)

	fmt.Println(masked)
	// Output:
	// user ****************** paid with ****************
}
