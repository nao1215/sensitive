package embargo_test

import (
	"fmt"
	"strings"

	"github.com/nao1215/embargo"
)

func ExampleKindCredential() {
	// #nosec G101 -- Deliberately fictitious credential for a runnable masking example.
	text := "postgres://reader:forgotten@db.example/orders"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
	fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	// Output: postgres://reader:[REDACTED]@db.example/orders
}

func ExampleKindServiceToken() {
	text := "upstream rejected sk-proj-" + strings.Repeat("Fake0", 8)
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindServiceToken))
	fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	// Output: upstream rejected [REDACTED]
}

func ExampleKindHighEntropy() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindHighEntropy))
	findings := scanner.ScanString("q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg")
	fmt.Println(len(findings), findings[0].Confidence)
	// Output: 1 0.3
}
