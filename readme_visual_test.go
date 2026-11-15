package embargo_test

import (
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestReadmeTestSnippets(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("(?s)<!-- test: ([^:]+):(Test\\w+) -->\\n```go\\n(.*?)\\n```").FindAllStringSubmatch(string(data), -1)
	if len(blocks) != 1 {
		t.Fatal("README must show the real output-check test")
	}
	for _, block := range blocks {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, block[1], nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		snippet, err := parser.ParseFile(fset, "snippet.go", "package embargo_test\n"+block[3], 0)
		if err != nil {
			t.Fatal(err)
		}
		snippetFunc, ok := snippet.Decls[0].(*ast.FuncDecl)
		if !ok {
			t.Fatal("snippet must be a function")
		}
		found := false
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Name.Name == block[2] {
				found = true
				if canonicalExample(t, fset, fn.Body) != canonicalExample(t, fset, snippetFunc.Body) {
					t.Fatal("README test differs from the executable test")
				}
			}
		}
		if !found {
			t.Fatal("README test not found")
		}
	}
}

func TestReadmeMaskingFigure(t *testing.T) {
	t.Parallel()
	file, err := parser.ParseFile(token.NewFileSet(), "masking_example_test.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string][]string{}
	for _, example := range doc.Examples(file) {
		outputs[example.Name] = strings.Split(strings.TrimSpace(example.Output), "\n")
	}
	log, overlap := outputs["Mask_log"], outputs["Mask_overlap"]
	//nolint:gocritic // Markdown code spans need literal backticks, not Go string quoting.
	table := fmt.Sprintf("| Operation | Actual text |\n|---|---|\n| Input | `%s` |\n| [Mask](masking_example_test.go) | `%s` |\n| [MaskFunc: keep last four](masking_example_test.go) | `%s` |\n| [Overlapping matches](masking_example_test.go) | `%s` with `%s` → `%s` |\n", log[0], log[1], log[2], overlap[0], overlap[1], overlap[2])
	syncVisualDocument(t, "README.md", "masking", table)
	//nolint:dupword,gocritic // Mermaid labels and consecutive edges require literal quotes and repeated node names.
	diagram := fmt.Sprintf("```mermaid\nflowchart LR\n  input[\"%s\"] --> first[\"Match: %s\"]\n  input --> second[\"Match: %s\"]\n  first --> union[\"Merge overlapping spans\"]\n  second --> union\n  union --> output[\"%s\"]\n```\n", overlap[0], strings.Fields(overlap[1])[0], strings.Fields(overlap[1])[1], overlap[2])
	syncVisualDocument(t, "doc/masking.md", "overlap", diagram)
}

func syncVisualDocument(t *testing.T, path, name, content string) {
	t.Helper()
	// #nosec G304 -- tests pass fixed repository documentation paths.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	start, end := "<!-- "+name+":start -->\n", "<!-- "+name+":end -->"
	before, rest, ok := strings.Cut(string(data), start)
	if !ok {
		t.Fatal("missing figure start")
	}
	actual, after, ok := strings.Cut(rest, end)
	if !ok {
		t.Fatal("missing figure end")
	}
	if os.Getenv("UPDATE_DOCS") == "1" {
		// #nosec G703 -- tests pass fixed repository documentation paths.
		if err := os.WriteFile(path, []byte(before+start+content+end+after), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if actual != content {
		t.Fatal("figure differs from runnable Examples; run make masking-doc")
	}
}
