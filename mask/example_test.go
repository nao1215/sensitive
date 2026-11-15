package mask_test

import (
	"fmt"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/mask"
)

func ExampleMask() {
	scanner := embargo.NewScanner(embargo.WithPAN(), embargo.WithEmail())
	text := "user tanaka@example.com paid with 4532015112830366"
	findings := scanner.ScanString(text)

	// Apply different masking strategies per detector.
	masked := mask.Mask(text, findings, map[embargo.DetectorName]mask.Strategy{
		"pan":   mask.Last4,
		"email": mask.Partial,
	})

	fmt.Println(masked)
	// Output:
	// user t*****@example.com paid with ************0366
}

func ExampleMask_strategies() {
	text := "4532015112830366"
	findings := embargo.NewScanner(embargo.WithPAN()).ScanString(text)
	for _, strategy := range []mask.Strategy{mask.Redact, mask.Last4, mask.First1Last4, mask.Partial, mask.Hash} {
		fmt.Println(mask.Mask(text, findings, map[embargo.DetectorName]mask.Strategy{
			"pan": strategy,
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
	scanner := embargo.NewScanner(embargo.WithPAN(), embargo.WithEmail())
	text := "user tanaka@example.com paid with 4532015112830366"
	findings := scanner.ScanString(text)

	// Apply the same strategy to all findings.
	masked := mask.MaskAll(text, findings, mask.Redact)

	fmt.Println(masked)
	// Output:
	// user ****************** paid with ****************
}
