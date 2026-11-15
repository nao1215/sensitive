package embargo_test

import (
	"math"
	"reflect"
	"slices"
	"testing"

	"github.com/nao1215/embargo"
)

type literalDetector []embargo.Finding

func (d literalDetector) Scan([]byte) []embargo.Finding { return slices.Clone(d) }

func TestScannerSelection(t *testing.T) {
	t.Parallel()
	const text = "alice@example.com 192.0.2.1 cvv: 123"
	all := embargo.NewScanner().ScanString(text)
	var zero embargo.Scanner
	if !reflect.DeepEqual(all, zero.ScanString(text)) || !reflect.DeepEqual(all, embargo.NewScanner(embargo.WithAll()).ScanString(text)) {
		t.Fatal("default and explicit all must agree")
	}
	for _, kind := range []embargo.Kind{embargo.KindEmail, embargo.KindIPAddr, embargo.KindCVV} {
		if !slices.ContainsFunc(all, func(f embargo.Finding) bool { return f.Kind == kind }) {
			t.Fatalf("default missing %s", kind)
		}
	}
	s := embargo.NewScanner(embargo.WithAll(), embargo.WithKinds(embargo.KindEmail, embargo.KindEmail))
	if got := s.ScanString(text); len(got) != 1 || got[0].Kind != embargo.KindEmail {
		t.Fatalf("selection: %v", got)
	}
	if got := embargo.NewScanner(embargo.WithKinds()).ScanString(text); len(got) != 0 {
		t.Fatal("empty selection enables builtins")
	}
}

func TestScannerOverlapsAndValidation(t *testing.T) {
	t.Parallel()
	a := embargo.Finding{Kind: "custom", Start: 0, End: 5, Confidence: .8}
	b := embargo.Finding{Kind: "other", Start: 1, End: 4, Confidence: 1}
	s := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(literalDetector{b, a}))
	if got := s.ScanString("token"); !reflect.DeepEqual(got, []embargo.Finding{a, b}) {
		t.Fatal(got)
	}
	for _, score := range []float64{-1, 2, math.NaN(), math.Inf(1)} {
		t.Run("invalid score", func(t *testing.T) {
			t.Parallel()
			mustPanic(t, func() { embargo.NewScanner(embargo.WithMinConfidence(score)) })
		})
	}
	mustPanic(t, func() { embargo.NewScanner(embargo.WithKinds("unknown")) })
	mustPanic(t, func() { embargo.NewScanner(embargo.WithDetector(nil)) })
	var pointer *literalDetector
	mustPanic(t, func() { embargo.NewScanner(embargo.WithDetector(pointer)) })
	for _, f := range []embargo.Finding{{Kind: "x", End: 6}, {Kind: "x", Start: -1, End: 1}, {Kind: "x", End: 1, Confidence: math.NaN()}, {End: 1}} {
		t.Run("invalid finding", func(t *testing.T) {
			t.Parallel()
			mustPanic(t, func() {
				embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(literalDetector{f})).ScanString("token")
			})
		})
	}
}

func mustPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	fn()
}

func TestMaskUnion(t *testing.T) {
	t.Parallel()
	input := []embargo.Finding{{Kind: "a", Start: 1, End: 4, Confidence: .5}, {Kind: "b", Start: 3, End: 6, Confidence: 1}, {Kind: "c", Start: 6, End: 7, Confidence: 1}}
	before := slices.Clone(input)
	if got := embargo.Mask("012345678", input); got != "0[REDACTED][REDACTED]78" {
		t.Fatal(got)
	}
	if got := embargo.MaskFunc("012345678", input, func(k embargo.Kind, v string) string { return string(k) + ":" + v }); got != "0b:12345c:678" {
		t.Fatal(got)
	}
	if !reflect.DeepEqual(input, before) {
		t.Fatal("mutated findings")
	}
	if got := embargo.Mask("safe", []embargo.Finding{{Start: -1, End: 1}}); got != "[REDACTED]" {
		t.Fatal(got)
	}
	mustPanic(t, func() { embargo.MaskFunc("", nil, nil) })
}
