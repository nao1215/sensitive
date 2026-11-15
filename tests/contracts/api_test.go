package contracts

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestPublicAPI(t *testing.T) {
	t.Parallel()
	loaded, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedTypes | packages.NeedImports | packages.NeedDeps}, "github.com/nao1215/embargo", "github.com/nao1215/embargo/embargotest")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 {
		t.Fatal("all public packages must load")
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].PkgPath < loaded[j].PkgPath })
	for _, pkg := range loaded {
		if len(pkg.Errors) > 0 {
			t.Fatal(pkg.Errors)
		}
		got := publicAPI(pkg.Types)
		path := filepath.Join("testdata", pkg.Name+".golden")
		if os.Getenv("UPDATE_API") == "1" {
			if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path) // #nosec G304 -- names come only from the two explicitly loaded local packages.
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Fatalf("public API changed in %s; review the API golden and CHANGELOG together\n%s", pkg.Name, got)
		}
	}
}

//nolint:gocognit // Enumerate all Go type shapes and both complete method sets in one audit.
func publicAPI(pkg *types.Package) string {
	qualifier := func(p *types.Package) string {
		if p == pkg {
			return ""
		}
		return p.Name()
	}
	var lines []string
	for _, name := range pkg.Scope().Names() {
		object := pkg.Scope().Lookup(name)
		if !object.Exported() {
			continue
		}
		typeName, ok := object.(*types.TypeName)
		if !ok {
			if value, isConstant := object.(*types.Const); isConstant {
				lines = append(lines, types.ObjectString(object, qualifier)+" = "+value.Val().ExactString())
				continue
			}
			lines = append(lines, types.ObjectString(object, qualifier))
			continue
		}
		named, ok := typeName.Type().(*types.Named)
		if !ok {
			lines = append(lines, types.ObjectString(object, qualifier))
			continue
		}
		signature := "type " + name
		if params := named.TypeParams(); params.Len() > 0 {
			var items []string
			for p := range params.TypeParams() {
				items = append(items, p.Obj().Name()+" "+types.TypeString(p.Constraint(), qualifier))
			}
			signature += "[" + strings.Join(items, ", ") + "]"
		}
		switch underlying := named.Underlying().(type) {
		case *types.Struct:
			signature += " struct"
			for i := range underlying.NumFields() {
				field := underlying.Field(i)
				// An embedded field promotes its exported fields and methods,
				// even when the embedded type itself is unexported.
				if field.Embedded() {
					panic("public struct embedding is forbidden")
				}
				if field.Exported() {
					lines = append(lines, strings.TrimSpace(name+"."+field.Name()+" "+types.TypeString(field.Type(), qualifier)+" "+strconvQuote(underlying.Tag(i))))
				}
			}
		case *types.Interface:
			signature += " interface"
			sealed := false
			for method := range underlying.Methods() {
				if method.Exported() {
					lines = append(lines, types.ObjectString(method, qualifier))
				} else {
					sealed = true
				}
			}
			if sealed {
				signature += " (sealed)"
			}
		default:
			signature += " " + types.TypeString(underlying, qualifier)
		}
		lines = append(lines, signature)
		// The pointer method set holds value and pointer methods, including
		// methods promoted from embedded types.
		for _, receiver := range []types.Type{named, types.NewPointer(named)} {
			methods := types.NewMethodSet(receiver)
			for selection := range methods.Methods() {
				if method := selection.Obj(); method.Exported() {
					lines = append(lines, "methodset "+types.TypeString(receiver, qualifier)+" "+types.ObjectString(method, qualifier))
				}
			}
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func strconvQuote(s string) string {
	if s == "" {
		return ""
	}
	return fmt.Sprintf("%q", s)
}

func TestAPIGoldenIncludesConstantValues(t *testing.T) {
	t.Parallel()
	pkg := types.NewPackage("fixture", "fixture")
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "Marker", types.Typ[types.String], constant.MakeString("value")))
	if !strings.Contains(publicAPI(pkg), `= "value"`) {
		t.Fatal("constant value is missing from golden")
	}
}

func TestAPIGoldenRejectsPromotedMembers(t *testing.T) {
	t.Parallel()
	pkg := types.NewPackage("fixture", "fixture")
	private := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "private", nil), types.NewStruct(nil, nil), nil)
	exported := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "Public", nil), types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "private", private, true)}, nil), nil)
	pkg.Scope().Insert(exported.Obj())
	defer func() {
		if recover() == nil {
			t.Error("unreviewed embedded member accepted")
		}
	}()
	publicAPI(pkg)
}
