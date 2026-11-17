package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type item struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Package string `json:"package"`
	Text    string `json:"text"`
	Line    int    `json:"line"`
}

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	root := ".."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	var items []item
	// #nosec G703 -- The explicit local source tree is the CLI input, not untrusted application data.
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".") && rel != "." || entry.Name() == "testdata" || rel == "tests" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		found, err := extract(path, rel)
		items = append(items, found...)
		return err
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(items)
}

func extract(path, rel string) ([]item, error) {
	set := token.NewFileSet()
	f, err := parser.ParseFile(set, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var items []item
	add := func(name string, doc *ast.CommentGroup, pos token.Pos) {
		text := ""
		if doc != nil {
			text = doc.Text()
		}
		items = append(items, item{Path: filepath.ToSlash(rel), Name: name, Package: filepath.ToSlash(filepath.Dir(rel)), Text: text, Line: set.Position(pos).Line})
	}
	test := strings.HasSuffix(path, "_test.go")
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if test && strings.HasPrefix(d.Name.Name, "Example") {
				add(d.Name.Name, d.Doc, d.Pos())
				exampleBody(f, d, add)
			} else if !test && ast.IsExported(d.Name.Name) {
				add(d.Name.Name, d.Doc, d.Pos())
			}
		case *ast.GenDecl:
			if !test {
				declarations(d, add)
			}
		}
	}
	return items, nil
}

func exampleBody(file *ast.File, d *ast.FuncDecl, add func(string, *ast.CommentGroup, token.Pos)) {
	if d.Body == nil {
		return
	}
	for _, comment := range file.Comments {
		if comment.Pos() > d.Body.Pos() && comment.End() < d.Body.End() {
			add(d.Name.Name+"/comment", comment, comment.Pos())
		}
	}
	ast.Inspect(d.Body, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err == nil {
			add(d.Name.Name+"/literal", &ast.CommentGroup{List: []*ast.Comment{{Slash: lit.Pos(), Text: "// " + value}}}, lit.Pos())
		}
		return true
	})
}

func declarations(d *ast.GenDecl, add func(string, *ast.CommentGroup, token.Pos)) {
	for _, spec := range d.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if !ast.IsExported(s.Name.Name) {
				continue
			}
			add(s.Name.Name, specDoc(s.Doc, d), s.Pos())
			fields(s, add)
		case *ast.ValueSpec:
			for _, name := range s.Names {
				if !ast.IsExported(name.Name) {
					continue
				}
				add(name.Name, specDoc(s.Doc, d), s.Pos())
			}
		}
	}
}

// specDoc is a spec's own documentation, or its declaration group's when the
// spec has none.
func specDoc(doc *ast.CommentGroup, d *ast.GenDecl) *ast.CommentGroup {
	if doc == nil {
		return d.Doc
	}
	return doc
}

func fields(s *ast.TypeSpec, add func(string, *ast.CommentGroup, token.Pos)) {
	var list *ast.FieldList
	switch node := s.Type.(type) {
	case *ast.StructType:
		list = node.Fields
	case *ast.InterfaceType:
		list = node.Methods
	default:
		return
	}
	for _, field := range list.List {
		for _, name := range field.Names {
			if ast.IsExported(name.Name) {
				add(s.Name.Name+"."+name.Name, field.Doc, field.Pos())
			}
		}
	}
}
