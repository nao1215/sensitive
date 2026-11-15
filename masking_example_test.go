package embargo_test

import (
	"fmt"

	"github.com/nao1215/embargo"
)

//nolint:goconst // The Example shows the literal redaction output.
func ExampleMask_log() {
	text := "INFO checkout email=alice@example.com card=4111111111111111"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	findings := scanner.ScanString(text)

	fmt.Println(text)
	fmt.Println(embargo.Mask(text, findings))
	fmt.Println(embargo.MaskFunc(text, findings, func(kind embargo.Kind, value string) string {
		if kind == embargo.KindPAN {
			return "[REDACTED]" + value[len(value)-4:]
		}
		return "[REDACTED]"
	}))

	// Output:
	// INFO checkout email=alice@example.com card=4111111111111111
	// INFO checkout email=[REDACTED] card=[REDACTED]
	// INFO checkout email=[REDACTED] card=[REDACTED]1111
}

func ExampleMask_overlap() {
	text := "token=abcdef"
	findings := []embargo.Finding{
		{Kind: "first", Start: 6, End: 10, Confidence: 1},
		{Kind: "second", Start: 8, End: 12, Confidence: 1},
	}

	fmt.Println(text)
	fmt.Println(text[findings[0].Start:findings[0].End], text[findings[1].Start:findings[1].End])
	fmt.Println(embargo.Mask(text, findings))

	// Output:
	// token=abcdef
	// abcd cdef
	// token=[REDACTED]
}
