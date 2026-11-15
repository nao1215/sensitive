package contracts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

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
