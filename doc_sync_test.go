package sensitive_test

import (
	"bytes"
	"go/ast"
	"go/doc"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReadmeExamples(t *testing.T) {
	t.Parallel()
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme = bytes.ReplaceAll(readme, []byte("\r\n"), []byte("\n"))
	blocks := regexp.MustCompile("(?s)<!-- example: ([^:\n]+):(Example\\w*) -->\n```go\n(.*?)\n```").FindAllSubmatch(readme, -1)
	if len(blocks) == 0 || len(blocks) != bytes.Count(readme, []byte("```go\n")) {
		t.Fatal("every README Go block must have an example: file:function marker")
	}
	for _, block := range blocks {
		t.Run(string(block[2]), func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, string(block[1]), nil, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			var want *doc.Example
			for _, example := range doc.Examples(file) {
				if "Example"+example.Name == string(block[2]) {
					want = example
				}
			}
			if want == nil {
				t.Fatalf("example %s not found in %s", block[2], block[1])
			}

			source := string(block[3])
			program := strings.HasPrefix(source, "package main\n")
			if program {
				source = strings.Replace(source, "package main", "package snippet_test", 1)
				source = strings.Replace(source, "func main()", "func Example()", 1)
			} else {
				source = "package snippet_test\nfunc Example() {\n" + source + "\n}"
			}
			snippet, err := parser.ParseFile(fset, "snippet_test.go", source, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			examples := doc.Examples(snippet)
			if len(examples) != 1 {
				t.Fatalf("README snippet contains %d examples, want 1", len(examples))
			}
			got := examples[0]
			if got.Output != want.Output || got.EmptyOutput != want.EmptyOutput || got.Unordered != want.Unordered {
				t.Fatalf("README output differs from %s", block[2])
			}
			gotCode, wantCode := got.Code, want.Code
			if program {
				if got.Play == nil || want.Play == nil {
					t.Fatal("quick start must be a standalone runnable program")
				}
				gotCode, wantCode = got.Play, want.Play
			}
			if canonicalExample(t, fset, gotCode) != canonicalExample(t, fset, wantCode) {
				t.Fatalf("README code differs from %s in %s; update both together", block[2], block[1])
			}
		})
	}
}

// canonicalExample ignores layout and comments; Output is checked separately.
func canonicalExample(t *testing.T, fset *token.FileSet, node ast.Node) string {
	t.Helper()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, node); err != nil {
		t.Fatal(err)
	}
	source := buf.String()
	if _, ok := node.(*ast.BlockStmt); ok {
		source = "package main\nfunc main() " + source
	}
	cleanSet := token.NewFileSet()
	clean, err := parser.ParseFile(cleanSet, "example.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := format.Node(&buf, cleanSet, clean); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestExamplesAppearInGodoc(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{".", "detector", "mask"} {
		t.Run(dir, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
			if err != nil {
				t.Fatal(err)
			}
			var files []*ast.File
			want := make(map[string]bool)
			for _, path := range paths {
				if strings.HasSuffix(path, "_test.go") && !strings.HasSuffix(path, "example_test.go") {
					continue
				}
				file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, file)
				if strings.HasSuffix(path, "_test.go") {
					for _, example := range doc.Examples(file) {
						want[example.Name] = true
						if example.Output == "" && !example.EmptyOutput || example.Unordered {
							t.Errorf("Example%s needs an ordered Output block", example.Name)
						}
						if example.Play == nil {
							t.Errorf("Example%s cannot render as a playground program", example.Name)
						}
					}
				}
			}
			pkg, err := doc.NewFromFiles(fset, files, "github.com/nao1215/sensitive/"+dir)
			if err != nil {
				t.Fatal(err)
			}
			check := func(examples []*doc.Example) {
				for i, example := range examples {
					delete(want, example.Name)
					if i > 0 && examples[i-1].Suffix > example.Suffix {
						t.Error("examples are not ordered by suffix")
					}
				}
			}
			check(pkg.Examples)
			for _, fn := range pkg.Funcs {
				check(fn.Examples)
			}
			for _, typ := range pkg.Types {
				check(typ.Examples)
				for _, fn := range typ.Funcs {
					check(fn.Examples)
				}
				for _, method := range typ.Methods {
					check(method.Examples)
				}
			}
			for name := range want {
				t.Errorf("Example%s is not attached to a documented symbol", name)
			}
		})
	}
}
