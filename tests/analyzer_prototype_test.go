package tests

import (
	"go/ast"
	"go/types"
	"testing"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

// Prototype only: a name rule cannot see masking handler configuration or
// arbitrary domain formatting contracts. Keep the measured counterexamples.
func TestSecretNameAnalyzerPrototype(t *testing.T) {
	t.Parallel()
	loaded, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps, Dir: "testdata/analyzerprobe"}, ".")
	if err != nil || len(loaded) != 1 {
		t.Fatal("prototype package load failed")
	}
	pkg := loaded[0]
	if len(pkg.Errors) > 0 {
		t.Fatal(pkg.Errors)
	}
	var diagnostics []analysis.Diagnostic
	analyzer := &analysis.Analyzer{Name: "embargoprototype", Doc: "Prototype of a logger argument name rule.", Run: runSecretNamePrototype}
	pass := &analysis.Pass{Analyzer: analyzer, Fset: pkg.Fset, Files: pkg.Syntax, Pkg: pkg.Types, TypesInfo: pkg.TypesInfo, Report: func(d analysis.Diagnostic) { diagnostics = append(diagnostics, d) }}
	if _, err := analyzer.Run(pass); err != nil {
		t.Fatal(err)
	}
	// Two intended findings and three safe uses: 40% precision on this adversarial
	// fixture, plus an opaque-name false negative. Do not publish this as a linter.
	if len(diagnostics) != 5 {
		t.Fatalf("prototype changed: %d diagnostics", len(diagnostics))
	}
}

//nolint:gocognit // Prototype walks only direct argument names and intentionally exposes its limits.
func runSecretNamePrototype(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := selector.Sel.Name
			if name != "Info" && name != "Error" && name != "Warn" && name != "Debug" {
				return true
			}
			function, ok := pass.TypesInfo.Uses[selector.Sel].(*types.Func)
			if !ok || function.Pkg() == nil || function.Pkg().Path() != "log/slog" {
				return true
			}
			for _, arg := range call.Args {
				var name string
				switch value := arg.(type) {
				case *ast.Ident:
					name = value.Name
				case *ast.SelectorExpr:
					name = value.Sel.Name
				}
				switch name {
				case comparisonPasswordKey, "Password", scenarioTokenKey, "Token", "secret", "Secret":
				default:
					continue
				}
				if named, ok := pass.TypesInfo.TypeOf(arg).(*types.Named); ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "github.com/nao1215/embargo" && named.Obj().Name() == "Secret" {
					continue
				}
				pass.Reportf(arg.Pos(), "sensitive name passed to logger")
			}
			return true
		})
	}
	return struct{}{}, nil
}
