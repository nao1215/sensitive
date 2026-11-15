package contracts

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
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
	want := []string{"github.com/nao1215/embargo", "github.com/nao1215/embargo/embargotest", "github.com/nao1215/embargo/internal/ascii", "github.com/nao1215/embargo/internal/detect"}
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
