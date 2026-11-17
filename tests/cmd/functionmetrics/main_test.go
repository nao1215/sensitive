package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

const (
	testFunctionName = "scan"
	testSourceFile   = "scanner.go"
)

func TestMetricsIncludeClosuresAndBooleanDecisions(t *testing.T) {
	t.Parallel()
	set := token.NewFileSet()
	source := `package fixture
func scan(a,b bool) { if a&&b { run:=func(){for a||b {break}};run() };switch {case a: return; default: return} }
`
	file, err := parser.ParseFile(set, "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	decl, ok := file.Decls[0].(*ast.FuncDecl)
	if !ok {
		t.Fatal("fixture does not contain a function")
	}
	got := functionMetric(set, "fixture.go", decl)
	if got.Statements != 8 || got.Cyclomatic != 6 || got.Lines != 1 {
		t.Fatal(got)
	}
}

func TestGrowthRequiresBaselineUpdate(t *testing.T) {
	t.Parallel()
	original := metric{File: testSourceFile, Name: testFunctionName, Statements: 10, Cyclomatic: 3, Lines: 20}
	for _, change := range []metric{{File: testSourceFile, Name: testFunctionName, Statements: 11, Cyclomatic: 3, Lines: 20}, {File: testSourceFile, Name: testFunctionName, Statements: 10, Cyclomatic: 4, Lines: 20}} {
		if check([]metric{change}, []metric{original}) == nil {
			t.Fatal("growth accepted")
		}
		if err := check([]metric{change}, []metric{change}); err != nil {
			t.Fatal(err)
		}
	}
	smaller := original
	smaller.Statements--
	smaller.Cyclomatic--
	if err := check([]metric{smaller}, []metric{original}); err != nil {
		t.Fatal(err)
	}
}

func TestNewLargestAndRemovedFunctionsRequireReview(t *testing.T) {
	t.Parallel()
	original := metric{File: testSourceFile, Name: testFunctionName, Statements: 10, Cyclomatic: 3, Lines: 20}
	added := metric{File: "new.go", Name: "large", Statements: 100, Cyclomatic: 30, Lines: 200}
	if check([]metric{original, added}, []metric{original}) == nil {
		t.Fatal("new largest function escaped review")
	}
	if check(nil, []metric{original}) == nil {
		t.Fatal("removed function baseline ignored")
	}
	if check([]metric{original}, []metric{original, original}) == nil {
		t.Fatal("duplicate entry accepted")
	}
}

func TestInventoryIncludesAdaptersAndExcludesFixtures(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, path := range []string{"root.go", "adapters/sdk/adapter.go", "root_test.go", "tests/fixture.go", "internal/detect/testdata/input.go"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("package fixture\nfunc scan(){return}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := measure(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatal(got)
	}
}
