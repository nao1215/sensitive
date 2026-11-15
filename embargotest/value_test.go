package embargotest_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

type valueProbe struct {
	testing.TB

	messages []string
}

func (p *valueProbe) Error(args ...any) { p.messages = append(p.messages, fmt.Sprint(args...)) }
func (p *valueProbe) Helper()           {}

type incompletePassword string

func (incompletePassword) String() string { return "hidden" }

//nolint:govet // The case table keeps names first for readability.
func TestCheckValue(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		build func(string) any
		safe  bool
	}{
		{"secret", func(s string) any { return embargo.NewSecret(s) }, true},
		{"input", func(s string) any {
			var v embargo.Input[string]
			if err := v.UnmarshalText([]byte(s)); err != nil {
				panic("fixture failed")
			}
			return v
		}, true},
		{"raw", func(s string) any { return s }, false},
		{"stringer-only", func(s string) any { return incompletePassword(s) }, false},
		{"constructor-panic", func(string) any { panic("must not print") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &valueProbe{TB: t}
			if embargotest.CheckValue(p, tc.build) != tc.safe {
				t.Fatal("wrong formatter verdict", p.messages)
			}
			if !tc.safe && len(p.messages) == 0 {
				t.Fatal("missing failure")
			}
			for _, message := range p.messages {
				if strings.Contains(message, "must not print") {
					t.Fatal("panic was printed")
				}
			}
		})
	}
}
