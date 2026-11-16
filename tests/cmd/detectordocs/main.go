package main

import (
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	startMarker   = "<!-- detectors:start -->"
	endMarker     = "<!-- detectors:end -->"
	defaultPrefix = " (NewScanner default: "
)

type kindDoc struct{ name, value, doc string }

func main() {
	check := flag.Bool("check", false, "fail if the generated README block differs")
	root := flag.String("root", "..", "repository root (default assumes go -C tests run)")
	flag.Parse()
	if err := update(*root, *check); err != nil {
		panic(err)
	}
}

func readKinds(path string) ([]kindDoc, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var result []kindDoc
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			found, err := readKindValues(value)
			if err != nil {
				return nil, err
			}
			result = append(result, found...)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("no Kind constants found")
	}
	return result, nil
}

func readKindValues(value *ast.ValueSpec) ([]kindDoc, error) {
	var result []kindDoc
	for i, name := range value.Names {
		if !strings.HasPrefix(name.Name, "Kind") {
			continue
		}
		if i >= len(value.Values) {
			return nil, fmt.Errorf("%s needs an explicit string value", name.Name)
		}
		literal, ok := value.Values[i].(*ast.BasicLit)
		if !ok {
			return nil, fmt.Errorf("%s is not a string literal", name.Name)
		}
		text, err := strconv.Unquote(literal.Value)
		if err != nil {
			return nil, err
		}
		doc := ""
		if value.Doc != nil {
			doc = strings.TrimSpace(value.Doc.Text())
		}
		result = append(result, kindDoc{name: name.Name, value: text, doc: doc})
	}
	return result, nil
}

// The first semicolon separates matching from validation; subsequent clauses
// stay in validation. The final parenthesis carries NewScanner's default.
// Cells are verbatim excerpts, never a second hand-maintained rule list: remove
// the identifier, take the first validation sentence, escape Markdown/HTML,
// and cut at a word boundary with an ellipsis when over 120 visible characters. The Kind link opens the full godoc.
func columns(kind kindDoc) (matches, checked, enabled string, err error) {
	matches, checked, ok := strings.Cut(kind.doc, "; ")
	validation := regexp.MustCompile(`(?i)\b(check\w*|validat\w*|verif\w*|structure|grammar|Shannon)\b`)
	if !strings.HasPrefix(matches, kind.name+" ") || !ok || !validation.MatchString(checked) {
		return "", "", "", fmt.Errorf("%s lacks godoc matching and validation clauses", kind.name)
	}
	checked, enabled, ok = strings.Cut(checked, defaultPrefix)
	if !ok || (enabled != "on)." && enabled != "off).") {
		return "", "", "", fmt.Errorf("%s lacks a NewScanner default", kind.name)
	}
	enabled = strings.TrimSuffix(enabled, ").")
	matches = strings.TrimPrefix(matches, kind.name+" ")
	checked, _, _ = strings.Cut(checked, ". ")
	return matches, checked, enabled, nil
}

func cell(text string) string {
	const limit = 120
	if utf8.RuneCountInString(text) > limit {
		cut := string([]rune(text)[:limit-2])
		if space := strings.LastIndexByte(cut, ' '); space >= 0 {
			cut = cut[:space]
		}
		text = strings.TrimRight(cut, ";,") + " …"
	}
	return strings.ReplaceAll(html.EscapeString(text), "|", "&#124;")
}

func render(kinds []kindDoc) (string, error) {
	rows := []string{startMarker, "| Kind | What it matches | How it is checked | Default |", "|---|---|---|---|"}
	for _, kind := range kinds {
		matches, checked, enabled, err := columns(kind)
		if err != nil {
			return "", err
		}
		rows = append(rows, "| ["+kind.name+"](https://pkg.go.dev/github.com/nao1215/embargo@main#"+kind.name+") | "+cell(matches)+" | "+cell(checked)+" | "+enabled+" |")
	}
	return strings.Join(append(rows, endMarker), "\n"), nil
}

func detectorBlock(readme string) (string, error) {
	if strings.Count(readme, startMarker) != 1 || strings.Count(readme, endMarker) != 1 {
		return "", errors.New("README needs one detectors block")
	}
	start, end := strings.Index(readme, startMarker), strings.Index(readme, endMarker)
	if end < start {
		return "", errors.New("reversed detectors markers")
	}
	return readme[start : end+len(endMarker)], nil
}

func update(root string, check bool) error {
	kinds, err := readKinds(filepath.Join(root, "finding.go"))
	if err != nil {
		return err
	}
	generated, err := render(kinds)
	if err != nil {
		return err
	}
	path := filepath.Join(root, "README.md")
	// #nosec G304 G703 -- The generator accepts a local repository root from its caller.
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	readme := strings.ReplaceAll(string(data), "\r\n", "\n")
	current, err := detectorBlock(readme)
	if err != nil {
		return err
	}
	if current == generated {
		return nil
	}
	if check {
		return errors.New("stale detectors block; run go -C tests run ./cmd/detectordocs")
	}
	const generatedFileMode = 0o600
	// #nosec G703 -- Only the caller-selected repository README is regenerated.
	return os.WriteFile(path, []byte(strings.Replace(readme, current, generated, 1)), generatedFileMode)
}
