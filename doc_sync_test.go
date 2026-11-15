package embargo_test

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

//nolint:gocognit // Walk the complete declaration or example structure so missing public contracts cannot be skipped.
func TestReadmeExamples(t *testing.T) {
	t.Parallel()
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme = bytes.ReplaceAll(readme, []byte("\r\n"), []byte("\n"))
	blocks := regexp.MustCompile("(?s)<!-- example: ([^:\n]+):(Example\\w*) -->\n```go\n(.*?)\n```").FindAllSubmatch(readme, -1)
	if len(blocks) == 0 || len(blocks)+bytes.Count(readme, []byte("<!-- test: ")) != bytes.Count(readme, []byte("```go\n")) {
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
			if string(block[2]) == "Example" && !program {
				t.Fatal("quick start must include package main and imports")
			}
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
				t.Fatalf("README code differs from %s in %s; update both together\nGOT:\n%s\nWANT:\n%s", block[2], block[1], canonicalExample(t, fset, gotCode), canonicalExample(t, fset, wantCode))
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
	checkPackageExamples(t, ".")
	checkPackageExamples(t, "embargotest")
}

//nolint:gocognit // Walk the complete declaration or example structure so missing public contracts cannot be skipped.
func checkPackageExamples(t *testing.T, dir string) {
	t.Helper()
	fset := token.NewFileSet()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	examples := map[string]*doc.Example{}
	required := map[string]bool{}
	for _, path := range paths {
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if strings.HasSuffix(path, "_test.go") {
			for _, e := range doc.Examples(file) {
				name := strings.SplitN(e.Name, "_", 3)
				key := e.Name
				if len(name) > 1 && name[len(name)-1] != "" && name[len(name)-1][0] >= 'a' && name[len(name)-1][0] <= 'z' {
					key = strings.Join(name[:len(name)-1], "_")
				}
				examples[key] = e
				if e.Output == "" || e.Unordered {
					t.Errorf("Example%s requires recognized ordered nonempty Output", e.Name)
				}
			}
			if !strings.Contains(filepath.Base(path), "example") {
				continue
			}
		} else {
			collectPublicExamples(file, required)
		}
		files = append(files, file)
	}
	if _, err = doc.NewFromFiles(fset, files, "github.com/nao1215/embargo"); err != nil {
		t.Fatal(err)
	}
	for name := range required {
		if examples[name] == nil {
			t.Errorf("%s: exported %s needs a runnable Example", dir, name)
		}
	}
	for name := range examples {
		if name != "" && !required[name] {
			t.Errorf("Example%s has no public identifier", name)
		}
	}
}

//nolint:gocognit // Walk the complete declaration or example structure so missing public contracts cannot be skipped.
func collectPublicExamples(file *ast.File, required map[string]bool) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if !d.Name.IsExported() {
				continue
			}
			name := d.Name.Name
			if d.Recv != nil {
				receiver := receiverName(d.Recv.List[0].Type)
				if !ast.IsExported(receiver) {
					continue
				}
				name = receiver + "_" + name
			}
			required[name] = true
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch v := spec.(type) {
				case *ast.ValueSpec:
					for _, n := range v.Names {
						if n.IsExported() {
							required[n.Name] = true
						}
					}
				case *ast.TypeSpec:
					if !v.Name.IsExported() {
						continue
					}
					required[v.Name.Name] = true
					if iface, ok := v.Type.(*ast.InterfaceType); ok {
						for _, field := range iface.Methods.List {
							for _, n := range field.Names {
								if n.IsExported() {
									required[v.Name.Name+"_"+n.Name] = true
								}
							}
						}
					}
				}
			}
		}
	}
}

func receiverName(expr ast.Expr) string {
	switch n := expr.(type) {
	case *ast.Ident:
		return n.Name
	case *ast.StarExpr:
		return receiverName(n.X)
	case *ast.IndexExpr:
		return receiverName(n.X)
	case *ast.IndexListExpr:
		return receiverName(n.X)
	default:
		panic("unsupported receiver")
	}
}

func TestExampleInventoryIgnoresPrivateReceivers(t *testing.T) {
	t.Parallel()
	source := `package fixture
 type private struct{}
 func (private) Error() string {return "fixed"}
 type Public struct{}
 func (Public) String() string {return "fixed"}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{}
	collectPublicExamples(file, required)
	if required["private_Error"] || !required["Public_String"] {
		t.Fatal("example inventory confused private and public receivers")
	}
}

func TestPublicExamplesOnlyImportPublicPackages(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"example_test.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, "/internal/") {
				t.Errorf("%s imports a private implementation", name)
			}
		}
	}
}
