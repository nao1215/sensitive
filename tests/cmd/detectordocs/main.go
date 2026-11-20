package main

import (
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	startMarker   = "<!-- detectors:start -->"
	endMarker     = "<!-- detectors:end -->"
	defaultPrefix = " (NewScanner default: "
)

type kindDoc struct{ name, value, doc string }

func main() {
	check := flag.Bool("check", false, "fail if the generated Kinds page block differs")
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

// defaultSetting returns "on" or "off" from a Kind's godoc after checking its
// contract: the first semicolon separates matching from validation, and the
// final parenthesis carries NewScanner's default. The Kinds page row shows the
// matching clause and links the Kind's godoc and its runnable Example instead
// of repeating the rest, so the rule lives only in the godoc.
func defaultSetting(kind kindDoc) (enabled string, err error) {
	matches, checked, ok := strings.Cut(kind.doc, "; ")
	validation := regexp.MustCompile(`(?i)\b(check\w*|validat\w*|verif\w*|structure|grammar|Shannon)\b`)
	if !strings.HasPrefix(matches, kind.name+" ") || !ok || !validation.MatchString(checked) {
		return "", fmt.Errorf("%s lacks godoc matching and validation clauses", kind.name)
	}
	_, enabled, ok = strings.Cut(checked, defaultPrefix)
	if !ok || (enabled != "on)." && enabled != "off).") {
		return "", fmt.Errorf("%s lacks a NewScanner default", kind.name)
	}
	return strings.TrimSuffix(enabled, ")."), nil
}

func render(kinds []kindDoc) (string, error) {
	rows := []string{startMarker, "| Kind | Matches | Example | Default |", "|---|---|---|---|"}
	for _, kind := range kinds {
		// The godoc must still carry its matching and validation clauses.
		enabled, err := defaultSetting(kind)
		if err != nil {
			return "", err
		}
		godoc := "https://pkg.go.dev/github.com/nao1215/embargo@main#"
		rows = append(rows, "| ["+kind.name+"]("+godoc+kind.name+") | "+matching(kind)+" | [Example]("+godoc+"example-"+kind.name+") | "+enabled+" |")
	}
	return strings.Join(append(rows, endMarker), "\n"), nil
}

// matchingWidth keeps a table cell within two lines on a wide page; the
// Kind's godoc, which the row links, has the whole clause.
const matchingWidth = 120

// matching is the godoc's first clause without the Kind name, as a table
// cell: "KindPAN finds 13–19 digits ...; ..." gives "Finds 13–19 digits ...".
// A longer clause is cut at a word before matchingWidth and ends in "…".
func matching(kind kindDoc) string {
	clause, _, _ := strings.Cut(strings.TrimPrefix(kind.doc, kind.name+" "), "; ")
	words := strings.Fields(clause)
	cell := ""
	for i, word := range words {
		next := strings.TrimSpace(cell + " " + word)
		limit := matchingWidth
		if i < len(words)-1 {
			limit -= len([]rune(" …"))
		}
		if len([]rune(next)) > limit {
			cell = strings.TrimRight(cell, ",") + " …"
			break
		}
		cell = next
	}
	return strings.ReplaceAll(strings.ToUpper(cell[:1])+cell[1:], "|", `\|`)
}

// pagePath is the site page that holds the generated table.
func pagePath(root string) string {
	return filepath.Join(root, "website", "content", "kinds.md")
}

func detectorBlock(readme string) (string, error) {
	if strings.Count(readme, startMarker) != 1 || strings.Count(readme, endMarker) != 1 {
		return "", errors.New("the Kinds page needs one detectors block")
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
	path := pagePath(root)
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
	// #nosec G703 -- Only the caller-selected repository page is regenerated.
	return os.WriteFile(path, []byte(strings.Replace(readme, current, generated, 1)), generatedFileMode)
}
