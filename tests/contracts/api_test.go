package contracts

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
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

// apiReason is one entry of doc/api-reasons.json: the case for keeping a
// group of public symbols, written so a reviewer can reject a weak one.
type apiReason struct {
	Implements string   `json:"implements,omitempty"`
	Need       string   `json:"need"`
	Without    string   `json:"without"`
	Symbols    []string `json:"symbols"`
}

// apiSurface is everything users can call, with the Example each item needs:
// a godoc Example name, "field" for struct fields or "e2e" for CLI flags.
type apiSurface struct {
	want     map[string]string
	examples map[string]map[string]string
	spec     string
	readme   string
}

// publicPackages are the directories whose exported identifiers users import.
func publicPackages() map[string]string {
	return map[string]string{
		".":                "embargo",
		"embargotest":      "embargotest",
		"adapters/grpc":    "embargogrpc",
		"adapters/logrus":  "embargologrus",
		"adapters/otel":    "embargootel",
		"adapters/sentry":  "embargosentry",
		"adapters/zap":     "embargozap",
		"adapters/zerolog": "embargozerolog",
	}
}

// standardMethods maps a method name to the standard interface that calls it.
// Such methods need a reason for implementing the interface, not their own.
func standardMethods() map[string]string {
	return map[string]string{
		"Format":        "fmt.Formatter",
		"String":        "fmt.Stringer",
		"LogValue":      "slog.LogValuer",
		"MarshalJSON":   "json.Marshaler",
		"UnmarshalJSON": "json.Unmarshaler",
		"MarshalText":   "encoding.TextMarshaler",
		"UnmarshalText": "encoding.TextUnmarshaler",
		"Scan":          "sql.Scanner",
	}
}

// vagueReasons are words that justify an API by taste instead of by a caller.
func vagueReasons() []string {
	return []string{"convenien", "shortcut", "completeness", "flexib", "future", "might ", "nice to", "symmetr", "for consistency", "just in case"}
}

func repositoryFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", path)) // #nosec G304 -- paths are fixed repository files.
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func loadAPISurface(t *testing.T) apiSurface {
	t.Helper()
	surface := apiSurface{want: map[string]string{}, examples: map[string]map[string]string{}, spec: repositoryFile(t, "e2e/atago/cli.atago.yaml"), readme: repositoryFile(t, "README.md")}
	for dir, name := range publicPackages() {
		files, err := filepath.Glob(filepath.Join("..", "..", dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if !strings.HasSuffix(path, "_test.go") {
				addFileSymbols(t, surface.want, name, path)
			}
		}
		surface.examples[name] = examples(t, filepath.Join(dir, "example_test.go"))
	}
	for line := range strings.SplitSeq(repositoryFile(t, "cmd/embargo/options.go"), "\n") {
		if rest, ok := strings.CutPrefix(line, "  --"); ok {
			surface.want["embargo --"+strings.Fields(rest)[0]] = "e2e"
		}
	}
	return surface
}

// addFileSymbols records the exported identifiers, methods and fields of one
// source file as "pkg.Name", "pkg.Type.Method" or "pkg.Type.Field".
func addFileSymbols(t *testing.T, symbols map[string]string, name, path string) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			addFunc(symbols, name, decl)
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				addSpec(symbols, name, spec)
			}
		}
	}
}

func addFunc(symbols map[string]string, name string, decl *ast.FuncDecl) {
	if !decl.Name.IsExported() {
		return
	}
	if decl.Recv == nil {
		symbols[name+"."+decl.Name.Name] = "Example" + decl.Name.Name
		return
	}
	if receiver := receiverName(decl.Recv.List[0].Type); ast.IsExported(receiver) {
		symbols[name+"."+receiver+"."+decl.Name.Name] = "Example" + receiver + "_" + decl.Name.Name
	}
}

func addSpec(symbols map[string]string, name string, spec ast.Spec) {
	switch spec := spec.(type) {
	case *ast.ValueSpec:
		for _, ident := range spec.Names {
			if ident.IsExported() {
				symbols[name+"."+ident.Name] = "Example" + ident.Name
			}
		}
	case *ast.TypeSpec:
		if !spec.Name.IsExported() {
			return
		}
		typeName := spec.Name.Name
		symbols[name+"."+typeName] = "Example" + typeName
		switch typ := spec.Type.(type) {
		case *ast.StructType:
			addMembers(symbols, name+"."+typeName+".", typ.Fields, "field")
		case *ast.InterfaceType:
			addMembers(symbols, name+"."+typeName+".", typ.Methods, "Example"+typeName+"_")
		}
	}
}

// addMembers records exported fields or interface methods. A prefix ending
// in "_" is an Example name to complete with the member name.
func addMembers(symbols map[string]string, prefix string, list *ast.FieldList, example string) {
	for _, member := range list.List {
		for _, ident := range member.Names {
			if !ident.IsExported() {
				continue
			}
			if strings.HasSuffix(example, "_") {
				symbols[prefix+ident.Name] = example + ident.Name
				continue
			}
			symbols[prefix+ident.Name] = example
		}
	}
}

func receiverName(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.StarExpr:
		return receiverName(expr.X)
	case *ast.IndexExpr:
		return receiverName(expr.X)
	case *ast.IndexListExpr:
		return receiverName(expr.X)
	case *ast.Ident:
		return expr.Name
	}
	return ""
}

// examples returns the bodies of the godoc Examples in one file, by name.
func examples(t *testing.T, path string) map[string]string {
	t.Helper()
	source := repositoryFile(t, path)
	file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	// An Example without an Output comment compiles but never runs, so it
	// would show readers output nobody checks.
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(fn.Name.Name, "Example") && !hasOutputComment(file, fn) {
			t.Errorf("%s: %s has no Output comment", path, fn.Name.Name)
		}
	}
	bodies := map[string]string{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(fn.Name.Name, "Example") {
			bodies[fn.Name.Name] = source[fn.Body.Pos()-1 : fn.Body.End()-1]
		}
	}
	return bodies
}

// hasOutputComment reports whether fn's body holds the Output or Unordered
// output comment that makes go test run it.
func hasOutputComment(file *ast.File, fn *ast.FuncDecl) bool {
	for _, group := range file.Comments {
		if group.Pos() < fn.Body.Pos() || group.End() > fn.Body.End() {
			continue
		}
		text := strings.TrimSpace(group.Text())
		if strings.HasPrefix(text, "Output:") || strings.HasPrefix(text, "Unordered output:") {
			return true
		}
	}
	return false
}

// hasExample accepts Example names with a lowercase suffix, as go doc does.
func hasExample(bodies map[string]string, want string) bool {
	for name := range bodies {
		suffix, found := strings.CutPrefix(name, want+"_")
		if name == want || found && suffix != "" && !ast.IsExported(suffix[:1]) {
			return true
		}
	}
	return false
}

// reasonProblems rejects an entry whose text argues from taste or is too short
// to name a caller and the code it would otherwise write.
func reasonProblems(reason apiReason) []string {
	var problems []string
	if len(reason.Symbols) == 0 {
		problems = append(problems, "entry has no symbols")
	}
	for _, text := range []string{reason.Need, reason.Without} {
		if len(text) < 60 {
			problems = append(problems, fmt.Sprintf("need and without must each say who calls it and what they would write instead (at least 60 characters): %q", text))
		}
		for _, word := range vagueReasons() {
			if strings.Contains(strings.ToLower(text), word) {
				problems = append(problems, fmt.Sprintf("%q is a taste, not a caller; name the caller and the code it saves", strings.TrimSpace(word)))
			}
		}
	}
	return problems
}

// groupProblem allows several symbols in one entry only for Kind constants and
// for methods that implement the same standard interface.
func (s apiSurface) groupProblem(reason apiReason, symbol string) string {
	parts := strings.Split(symbol, ".")
	switch {
	case reason.Implements != "":
		if len(parts) != 3 || standardMethods()[parts[2]] != reason.Implements {
			return symbol + " does not implement " + reason.Implements
		}
	case len(reason.Symbols) > 1:
		if len(parts) != 2 || !strings.HasPrefix(symbol, "embargo.Kind") || !strings.Contains(s.readme, "["+parts[1]+"](") {
			return symbol + ": only Kind constants listed in the README detector table share an entry"
		}
	}
	return ""
}

func (s apiSurface) exampleProblem(symbol string) string {
	parts := strings.Split(symbol, ".")
	switch example := s.want[symbol]; example {
	case "e2e":
		if !strings.Contains(s.spec, strings.TrimPrefix(symbol, "embargo ")) {
			return symbol + " has no scenario in e2e/atago/cli.atago.yaml"
		}
	case "field":
		if typeExample := "Example" + parts[1]; !strings.Contains(s.examples[parts[0]][typeExample], "."+parts[2]) {
			return symbol + " is not read in " + typeExample
		}
	default:
		if !hasExample(s.examples[parts[0]], example) {
			return symbol + " has no " + example + " in " + parts[0] + "'s example_test.go"
		}
	}
	return ""
}

// TestEveryPublicSymbolHasAReason keeps public API additions deliberate: each
// exported identifier, method, field and CLI flag must be named in exactly one
// entry of doc/api-reasons.json that says who needs it and what they would
// have to write without it, and must have its own Example.
func TestEveryPublicSymbolHasAReason(t *testing.T) {
	t.Parallel()
	var reasons []apiReason
	if err := json.Unmarshal([]byte(repositoryFile(t, "doc/api-reasons.json")), &reasons); err != nil {
		t.Fatal(err)
	}
	surface := loadAPISurface(t)
	seen := map[string]bool{}
	for _, reason := range reasons {
		label := strings.Join(reason.Symbols, ", ")
		for _, problem := range reasonProblems(reason) {
			t.Errorf("%s: %s", label, problem)
		}
		for _, symbol := range reason.Symbols {
			if seen[symbol] {
				t.Errorf("%s is listed in more than one api-reasons entry", symbol)
			}
			seen[symbol] = true
			if _, ok := surface.want[symbol]; !ok {
				t.Errorf("%s is in doc/api-reasons.json but not in the public API; remove the entry", symbol)
				continue
			}
			for _, problem := range []string{surface.groupProblem(reason, symbol), surface.exampleProblem(symbol)} {
				if problem != "" {
					t.Error(problem)
				}
			}
		}
	}
	missing := slices.Sorted(maps.Keys(surface.want))
	for _, symbol := range missing {
		if !seen[symbol] {
			t.Errorf("%s is public but has no entry in doc/api-reasons.json; add who needs it and what they would write without it, or keep it unexported", symbol)
		}
	}
}

func TestReasonProblemsRejectTasteAndShortText(t *testing.T) {
	t.Parallel()
	const symbol = "embargo.X"
	long := strings.Repeat("a caller that logs requests writes this ", 2)
	cases := map[string]apiReason{
		"no symbols": {Need: long, Without: long},
		"short":      {Symbols: []string{symbol}, Need: "it is useful", Without: long},
		"taste":      {Symbols: []string{symbol}, Need: long + "as a convenience", Without: long},
	}
	for name, reason := range cases {
		if len(reasonProblems(reason)) == 0 {
			t.Errorf("%s: weak reason accepted", name)
		}
	}
	if problems := reasonProblems(apiReason{Symbols: []string{symbol}, Need: long, Without: long}); len(problems) != 0 {
		t.Errorf("concrete reason rejected: %v", problems)
	}
}

func TestGroupedReasonsAreKindsOrOneInterface(t *testing.T) {
	t.Parallel()
	surface := apiSurface{readme: "[KindEmail](x) [KindPAN](x)"}
	if problem := surface.groupProblem(apiReason{Symbols: []string{"embargo.KindEmail", "embargo.KindPAN"}}, "embargo.KindPAN"); problem != "" {
		t.Error(problem)
	}
	if surface.groupProblem(apiReason{Symbols: []string{"embargo.KindEmail", "embargo.Mask"}}, "embargo.Mask") == "" {
		t.Error("a function grouped with kinds was accepted")
	}
	if surface.groupProblem(apiReason{Implements: "fmt.Stringer", Symbols: []string{"embargo.Secret.Reveal"}}, "embargo.Secret.Reveal") == "" {
		t.Error("Reveal accepted as fmt.Stringer")
	}
	if !hasExample(map[string]string{"ExampleMask_log": ""}, "ExampleMask") || hasExample(map[string]string{"ExampleMaskFunc": ""}, "ExampleMask") {
		t.Error("example suffix rule is wrong")
	}
}
