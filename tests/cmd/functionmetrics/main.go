// Command functionmetrics requires review of growth in the largest production functions.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type metric struct {
	File       string `json:"file"`
	Name       string `json:"name"`
	Statements int    `json:"statements"`
	Cyclomatic int    `json:"cyclomatic"`
	Lines      int    `json:"lines"`
}

type baseline struct {
	Functions []metric `json:"functions"`
	Schema    int      `json:"schema"`
}

func main() {
	if err := run(); err != nil {
		if _, writeErr := os.Stderr.WriteString(err.Error() + "\n"); writeErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

func run() error {
	root := flag.String("root", "..", "repository root")
	write := flag.Bool("write", false, "record current largest functions for review")
	flag.Parse()
	actual, err := measure(*root)
	if err != nil {
		return err
	}
	path := filepath.Join(*root, "doc", "function-baseline.json")
	// #nosec G304 G703 -- The tool reads the baseline in the caller-selected local repository.
	recorded, err := os.ReadFile(path)
	var previous baseline
	if err == nil {
		if decodeErr := json.Unmarshal(recorded, &previous); decodeErr != nil {
			return decodeErr
		}
	} else if !*write {
		return err
	}
	if *write {
		return writeBaseline(path, baseline{Schema: 1, Functions: watched(actual, previous.Functions)})
	}
	if previous.Schema != 1 {
		return errors.New("unsupported function baseline schema")
	}
	if err := check(actual, previous.Functions); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(watched(actual, previous.Functions))
}

// writeBaseline checks both JSON output and file-close errors.
func writeBaseline(path string, value baseline) error {
	const generatedFileMode = 0o600
	// #nosec G304 G703 -- Only the caller-selected repository baseline is regenerated.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, generatedFileMode)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return errors.Join(encoder.Encode(value), file.Close())
}

// Count statements and decisions including closures, using the same definitions
// for every revision. Block, case, communication and empty statements are excluded.
func functionMetric(set *token.FileSet, file string, decl *ast.FuncDecl) metric {
	name := decl.Name.Name
	if decl.Recv != nil {
		name = receiverName(decl.Recv.List[0].Type) + "." + name
	}
	result := metric{File: file, Name: name, Statements: 0, Cyclomatic: 1, Lines: set.Position(decl.End()).Line - set.Position(decl.Pos()).Line + 1}
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		result.Statements += statementCount(node)
		result.Cyclomatic += decisionCount(node)
		return true
	})
	return result
}

// receiverName is the first identifier in a receiver type, so pointer and
// generic receivers share the base type name.
func receiverName(receiver ast.Expr) string {
	name := ""
	ast.Inspect(receiver, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && name == "" {
			name = id.Name
		}
		return true
	})
	return name
}

// statementCount is 1 for a statement node other than a block, case,
// communication or empty statement.
func statementCount(node ast.Node) int {
	switch node.(type) {
	case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause, *ast.EmptyStmt:
	default:
		if _, ok := node.(ast.Stmt); ok {
			return 1
		}
	}
	return 0
}

// decisionCount is 1 for a branch, loop, non-default case or logical operator.
func decisionCount(node ast.Node) int {
	switch value := node.(type) {
	case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
		return 1
	case *ast.CaseClause:
		if value.List != nil {
			return 1
		}
	case *ast.CommClause:
		if value.Comm != nil {
			return 1
		}
	case *ast.BinaryExpr:
		if value.Op == token.LAND || value.Op == token.LOR {
			return 1
		}
	}
	return 0
}

func measure(root string) ([]metric, error) {
	set := token.NewFileSet()
	var result []metric
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return directoryAction(entry.Name(), relative)
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		result, err = appendFileMetrics(result, set, path, filepath.ToSlash(relative))
		return err
	})
	return result, err
}

// directoryAction skips version control, the separate tests module and
// fixture directories; every other directory is walked.
func directoryAction(name, relative string) error {
	if name == ".git" || relative == "tests" || name == "testdata" {
		return filepath.SkipDir
	}
	return nil
}

// appendFileMetrics parses one production file and appends a metric for each
// function with a body; declarations without bodies are skipped.
func appendFileMetrics(result []metric, set *token.FileSet, path, file string) ([]metric, error) {
	parsed, err := parser.ParseFile(set, path, nil, 0)
	if err != nil {
		return result, err
	}
	for _, decl := range parsed.Decls {
		if function, ok := decl.(*ast.FuncDecl); ok && function.Body != nil {
			result = append(result, functionMetric(set, file, function))
		}
	}
	return result, nil
}

func key(m metric) string { return m.File + ":" + m.Name }

// Keep the largest ten by each metric and previously reviewed functions, even
// when extraction makes them smaller. Removed functions leave the next baseline.
func watched(actual, previous []metric) []metric {
	const largestFunctionCount = 10
	selected := map[string]bool{}
	for _, m := range previous {
		selected[key(m)] = true
	}
	for _, score := range []func(metric) int{func(m metric) int { return m.Statements }, func(m metric) int { return m.Cyclomatic }} {
		ordered := slices.Clone(actual)
		slices.SortFunc(ordered, func(a, b metric) int {
			if delta := score(b) - score(a); delta != 0 {
				return delta
			}
			return strings.Compare(key(a), key(b))
		})
		for _, m := range ordered[:min(largestFunctionCount, len(ordered))] {
			selected[key(m)] = true
		}
	}
	focus := []string{"assignmentValue", "slogHandler.sanitizeAttr", "Scanner.scan", "Scanner.scanInput", "Recorder.run", "Recorder.Check", "logHTTPExchange", "ABARouting.scanNormalized", "JPPhone.scanNormalized", "run"}
	var result []metric
	for _, m := range actual {
		if selected[key(m)] || slices.Contains(focus, m.Name) {
			result = append(result, m)
		}
	}
	slices.SortFunc(result, func(a, b metric) int { return strings.Compare(key(a), key(b)) })
	return result
}

func check(actual, recorded []metric) error {
	limits := map[string]metric{}
	for _, m := range recorded {
		if _, exists := limits[key(m)]; exists {
			return errors.New("duplicate function baseline entry")
		}
		limits[key(m)] = m
	}
	for _, m := range watched(actual, recorded) {
		limit, exists := limits[key(m)]
		if !exists || m.Statements > limit.Statements || m.Cyclomatic > limit.Cyclomatic {
			return fmt.Errorf("function growth: %s has %d statements and CC %d; review and update doc/function-baseline.json in the same PR", key(m), m.Statements, m.Cyclomatic)
		}
		delete(limits, key(m))
	}
	if len(limits) > 0 {
		return errors.New("removed function still recorded: update the function baseline")
	}
	return nil
}
