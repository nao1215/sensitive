package embargotest_test

import (
	"errors"
	"fmt"
	"log/slog"
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

type panickingPassword struct{ embargo.Secret[string] }

func (panickingPassword) Format(fmt.State, rune) { panic("formatter failed") }

func TestCheckValueRejectsFormattingPanic(t *testing.T) {
	t.Parallel()
	p := &valueProbe{TB: t}
	if embargotest.CheckValue(p, func(s string) any { return panickingPassword{embargo.NewSecret(s)} }) {
		t.Fatal("fmt recovered a formatter panic but the contract passed")
	}
	if !strings.Contains(strings.Join(p.messages, "\n"), "fmt/%#v") {
		t.Fatal("missing exact failing formatter path")
	}
}

type panickingLogValue struct{ embargo.Secret[string] }

func (panickingLogValue) LogValue() slog.Value { panic("log value failed") }
func TestCheckValueRejectsLogValuePanic(t *testing.T) {
	t.Parallel()
	p := &valueProbe{TB: t}
	if embargotest.CheckValue(p, func(s string) any { return panickingLogValue{embargo.NewSecret(s)} }) {
		t.Fatal("slog panic accepted")
	}
	if !strings.Contains(strings.Join(p.messages, "\n"), "slog/json") {
		t.Fatal("missing exact failing slog path")
	}
}

type nestedPanicLogValue struct{ embargo.Secret[string] }

func (v nestedPanicLogValue) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("child", panickingLogValue(v)))
}

type cyclicLogValue struct{ embargo.Secret[string] }

func (v cyclicLogValue) LogValue() slog.Value { return slog.GroupValue(slog.Any("cycle", v)) }

type groupedLogValue struct{ embargo.Secret[string] }

func (v groupedLogValue) LogValue() slog.Value {
	return slog.GroupValue(slog.Group("nested", slog.Any("secret", v.Secret)))
}

func TestCheckValueAcceptsNestedSlogValue(t *testing.T) {
	t.Parallel()
	if !embargotest.CheckValue(t, func(s string) any { return groupedLogValue{embargo.NewSecret(s)} }) {
		t.Fatal("safe nested group rejected")
	}
}

type failedJSONValue struct{}

func (failedJSONValue) MarshalJSON() ([]byte, error) { return nil, errors.New("json failed") }

type failedJSONLogValue struct{ embargo.Secret[string] }

func (failedJSONLogValue) LogValue() slog.Value { return slog.AnyValue(failedJSONValue{}) }
func TestCheckValueRejectsNestedSlogFailures(t *testing.T) {
	t.Parallel()
	for _, build := range []func(string) any{
		func(s string) any { return nestedPanicLogValue{embargo.NewSecret(s)} },
		func(s string) any { return failedJSONLogValue{embargo.NewSecret(s)} },
		func(s string) any { return cyclicLogValue{embargo.NewSecret(s)} },
	} {
		p := &valueProbe{TB: t}
		if embargotest.CheckValue(p, build) {
			t.Error("failed nested slog value was accepted")
		}
		if !strings.Contains(strings.Join(p.messages, "\n"), "slog/json") {
			t.Error("missing exact failing path")
		}
	}
}

func TestCheckValueNamesUnexportedFieldLeak(t *testing.T) {
	t.Parallel()
	probe := &valueProbe{TB: t}
	embargotest.CheckValue(probe, func(s string) any { return incompletePassword(s) })
	if !strings.Contains(strings.Join(probe.messages, "\n"), "fmt/unexported/%v") {
		t.Fatal("missing unexported field diagnostic", probe.messages)
	}
}

type maskedError struct{ embargo.Secret[string] }

//nolint:goconst // Keep the error marker explicit as an independent expected output.
func (maskedError) Error() string { return "[REDACTED]" }

func TestCheckValueAcceptsMaskedError(t *testing.T) {
	t.Parallel()
	if !embargotest.CheckValue(t, func(canary string) any { return maskedError{embargo.NewSecret(canary)} }) {
		t.Fatal("safe error failed formatting and wrapping checks")
	}
}
