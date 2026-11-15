package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractCoversInterfaceAndExampleBody(t *testing.T) {
	t.Parallel()
	const source = `package fixture
// Reader consumes bytes.
type Reader interface {
// Read returns the next byte.
Read() byte
}
func ExampleReader() {
// A robust claim inside an Example must reach the prose checker.
println("simply done")
// Output: simply done
}
`
	for _, name := range []string{"fixture.go", "fixture_test.go"} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		items, err := extract(path, name)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, value := range items {
			seen[value.Name] = true
		}
		if name == "fixture.go" && !seen["Reader.Read"] {
			t.Fatal("interface method was omitted")
		}
		if name == "fixture_test.go" && (!seen["ExampleReader/comment"] || !seen["ExampleReader/literal"]) {
			t.Fatal("Example body was omitted")
		}
	}
}
