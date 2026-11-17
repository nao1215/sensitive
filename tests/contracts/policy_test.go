package contracts

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestRootModuleHasNoRequirements(t *testing.T) {
	t.Parallel()
	cmd := exec.CommandContext(t.Context(), "go", "mod", "edit", "-json")
	cmd.Dir = "../.."
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var module struct {
		//nolint:tagliatelle // go mod edit uses this exact JSON field name.
		Require []json.RawMessage `json:"Require"`
	}
	if err := json.Unmarshal(output, &module); err != nil {
		t.Fatal(err)
	}
	if len(module.Require) != 0 {
		t.Fatal("root module must have zero requirements")
	}
}

func TestProductionPackageInventory(t *testing.T) {
	t.Parallel()
	cmd := exec.CommandContext(t.Context(), "go", "list", "-f", "{{.ImportPath}}", "./...")
	cmd.Dir = "../.."
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(output))
	slices.Sort(got)
	want := []string{"github.com/nao1215/embargo", "github.com/nao1215/embargo/cmd/embargo", "github.com/nao1215/embargo/embargotest", "github.com/nao1215/embargo/internal/ascii", "github.com/nao1215/embargo/internal/detect", "github.com/nao1215/embargo/internal/output", "github.com/nao1215/embargo/internal/saferecord"}
	if !slices.Equal(got, want) {
		t.Fatalf("review the API and architecture for new packages: %v", got)
	}
}

func TestSecretFilesHaveNoRuntimeDependencies(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"secret.go", "input.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range f.Imports {
			path, err := strconv.Unquote(item.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.Split(path, "/")[0], ".") {
				t.Fatal("secret storage must depend only on standard interfaces")
			}
		}
	}
}

func TestRecorderDoesNotStartDetachedGoroutines(t *testing.T) {
	t.Parallel()
	paths, err := filepath.Glob("../../embargotest/*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path) // #nosec G304 -- paths come only from the local production-source glob.
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if _, ok := n.(*ast.GoStmt); ok {
				t.Error("Run must delegate joined child I/O to os/exec")
			}
			return true
		})
	}
}

// The lint exclusion is limited by filename and diagnostic. This AST check
// closes its remaining scope: helpers and Tests in those files stay strict.
func TestUncheckedPrintingIsOnlyInExamples(t *testing.T) {
	t.Parallel()
	err := filepath.WalkDir("../..", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.Contains(entry.Name(), "example") || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		checkPrintingScope(t, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func checkPrintingScope(t *testing.T, path string) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	qualifier := "fmt"
	for _, imp := range file.Imports {
		name, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if name == "fmt" && imp.Name != nil {
			qualifier = imp.Name.Name
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if fn, ok := node.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Example") && len(fn.Type.Params.List) == 0 && fn.Type.Results == nil {
			return false
		}
		expression := uncheckedExpression(node)
		call, ok := expression.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := selector.X.(*ast.Ident)
		if !ok || id.Name != qualifier {
			return true
		}
		switch selector.Sel.Name {
		case "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln":
			t.Errorf("%s: unchecked fmt output outside an Example; only Example functions are exempt", path)
		}
		return true
	})
}

func uncheckedExpression(node ast.Node) ast.Expr {
	var expression ast.Expr
	switch statement := node.(type) {
	case *ast.GoStmt:
		expression = statement.Call
	case *ast.DeferStmt:
		expression = statement.Call
	case *ast.ValueSpec:
		if len(statement.Names) == 2 && len(statement.Values) == 1 && statement.Names[1].Name == "_" {
			expression = statement.Values[0]
		}
	case *ast.ExprStmt:
		expression = statement.X
	case *ast.AssignStmt:
		if len(statement.Lhs) != 2 || len(statement.Rhs) != 1 {
			return nil
		}
		id, ok := statement.Lhs[1].(*ast.Ident)
		if !ok || id.Name != "_" {
			return nil
		}
		expression = statement.Rhs[0]
	default:
		return nil
	}
	return expression
}
