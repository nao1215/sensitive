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

func ExampleMask_strategies() {
	text := "4532015112830366"
	findings := sensitive.NewScanner(sensitive.WithPAN()).ScanString(text)
	for _, strategy := range []mask.Strategy{mask.Redact, mask.Last4, mask.First1Last4, mask.Partial, mask.Hash} {
		fmt.Println(mask.Mask(text, findings, map[sensitive.DetectorName]mask.Strategy{
			detector.NamePAN: strategy,
		}))
	}
	// Output:
	// ****************
	// ************0366
	// 4***********0366
	// ************0366
	// 9b089351
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
