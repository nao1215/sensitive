package embargo_test

import (
	"bytes"
	"go/ast"
	"go/doc"
	"go/format"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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
			gotCode, wantCode := got.Code, readmeExcerpt(t, file, want.Code)
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
	// Token comparison ignores source-position blank lines while retaining every
	// byte of string literals, including meaningful whitespace in raw strings.
	var lexer scanner.Scanner
	lexer.Init(token.NewFileSet().AddFile("formatted.go", -1, buf.Len()), buf.Bytes(), nil, 0)
	var tokens []string
	for {
		_, kind, literal := lexer.Scan()
		if kind == token.EOF {
			break
		}
		tokens = append(tokens, kind.String()+":"+strconv.Quote(literal))
	}
	return strings.Join(tokens, " ")
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

// readmeExcerpt keeps logger setup in the runnable Example while the README
// shows the application-facing calls between explicit source markers.
func readmeExcerpt(t *testing.T, file *ast.File, code ast.Node) ast.Node {
	t.Helper()
	body, ok := code.(*ast.BlockStmt)
	if !ok {
		return code
	}
	var start, end token.Pos
	for _, group := range file.Comments {
		if group.Pos() < body.Pos() || group.End() > body.End() {
			continue
		}
		switch strings.TrimSpace(group.Text()) {
		case "README:begin":
			start = group.End()
		case "README:end":
			end = group.Pos()
		}
	}
	if start == token.NoPos && end == token.NoPos {
		return code
	}
	if start == token.NoPos || end <= start {
		t.Fatal("invalid README excerpt markers")
	}
	var statements []ast.Stmt
	for _, statement := range body.List {
		if statement.Pos() > start && statement.End() < end {
			statements = append(statements, statement)
		}
	}
	if len(statements) == 0 {
		t.Fatal("empty README excerpt")
	}
	return &ast.BlockStmt{Lbrace: body.Lbrace, List: statements, Rbrace: body.Rbrace}
}

func readmeExampleFiles(t *testing.T) []string {
	t.Helper()
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, pattern := range []string{`<!-- example: ([^:]+):`, `\]\(([^)]+example[^)]*\.go)\)`} {
		for _, match := range regexp.MustCompile(pattern).FindAllSubmatch(readme, -1) {
			paths[string(match[1])] = true
		}
	}
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}
	sort.Strings(result)
	if len(result) == 0 {
		t.Fatal("README has no linked examples")
	}
	return result
}

func TestReadmeLinkedExamplesStandalone(t *testing.T) {
	t.Parallel()
	var compiler sync.Mutex
	// Compile one linked file at a time, without package peers or private helpers.
	for _, path := range readmeExampleFiles(t) {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			compiler.Lock()
			defer compiler.Unlock()
			checkStandaloneExampleFile(t, path)
		})
	}
}

func checkStandaloneExampleFile(t *testing.T, path string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	examples := doc.Examples(file)
	if len(examples) == 0 {
		t.Fatal("linked file has no runnable examples")
	}
	for _, example := range examples {
		if example.Play == nil || example.Output == "" || example.Unordered {
			t.Errorf("Example%s needs standalone code and ordered output in %s", example.Name, path)
		}
	}
	for _, imp := range file.Imports {
		if strings.Contains(imp.Path.Value, "/internal/") {
			t.Error("example imports private code")
		}
	}
	if t.Failed() {
		return
	}
	// A file-only package has no original API identifiers for go vet to resolve.
	// Generic example names preserve every body and Output assertion under vet.
	index := 0
	for _, decl := range file.Decls {
		if function, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(function.Name.Name, "Example") {
			function.Name.Name = "Example_standalone" + strconv.Itoa(index)
			index++
		}
	}
	var source bytes.Buffer
	if err := format.Node(&source, fset, file); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "example_test.go")
	if err := os.WriteFile(target, source.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	writeStandaloneModule(t, filepath.Dir(target), path)
	command := exec.CommandContext(t.Context(), "go", "test", "-mod=mod", "-count=1", ".")
	command.Dir = filepath.Dir(target)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("standalone %s: %v\n%s", path, err, output)
	}
	t.Logf("%d standalone examples passed", len(examples))
}

func TestStandaloneExamplesRejectMissingHelpers(t *testing.T) {
	t.Parallel()
	source := `package fixture_test
import "fmt"
func Example() {
 fmt.Println(privateValue())
 // Output: retained
}
`
	for _, helper := range []string{"", `func privateValue() string {return "retained"}`} {
		file, err := parser.ParseFile(token.NewFileSet(), "example_test.go", source+helper, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		examples := doc.Examples(file)
		if len(examples) != 1 || (examples[0].Play != nil) != (helper != "") {
			t.Fatal("standalone check accepted a missing helper or rejected a local helper")
		}
	}
}

func TestDefaultPolicyDocumentation(t *testing.T) {
	t.Parallel()
	root := openExampleRoot(t, ".")
	for _, path := range []string{"doc/masking.md", "doc/testing-output.md", "embargotest/detector.go"} {
		text, err := root.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{"25 built-ins", "37", "WithAll", "opt-in"} {
			if !strings.Contains(string(text), required) {
				t.Errorf("%s omits the v0.5 default contract %q", path, required)
			}
		}
		for _, stale := range []string{"enables every built-in", "default all-built-in policy", "reports some public random identifiers as high-entropy candidates", "WithMinConfidence(0.5)"} {
			if strings.Contains(string(text), stale) {
				t.Errorf("%s retains obsolete default claim %q", path, stale)
			}
		}
	}
	text, err := os.ReadFile("doc/logging.md")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), "Key rules apply to structured output, not arbitrary text") || !strings.Contains(string(text), "Credential assignments") {
		t.Error("raw Scan credential-key effects are not documented")
	}
}

func writeStandaloneModule(t *testing.T, directory, source string) {
	t.Helper()
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	directive := regexp.MustCompile(`(?m)^go \S+`).Find(original)
	if len(directive) == 0 {
		t.Fatal("missing Go version")
	}
	const module = "github.com/nao1215/embargo"
	text := "module example.com/embargo-readme\n" + string(directive) + "\nrequire " + module + " v0.0.0\nreplace " + module + " => " + strconv.Quote(root) + "\n"
	parts := strings.Split(filepath.ToSlash(source), "/")
	if len(parts) > 2 && parts[0] == "adapters" {
		adapter := module + "/adapters/" + parts[1]
		text += "require " + adapter + " v0.0.0\nreplace " + adapter + " => " + strconv.Quote(filepath.Join(root, "adapters", parts[1])) + "\n"
	}
	rootDir := openExampleRoot(t, directory)
	if err := rootDir.WriteFile("go.mod", []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func openExampleRoot(t *testing.T, directory string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}
