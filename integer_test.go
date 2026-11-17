package embargo

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"testing"
)

const exponentWhitespaceString = "0E00 "

func TestOutputMaskJSONNumberLexemes(t *testing.T) {
	t.Parallel()
	s := NewScanner()
	for _, in := range []string{
		`{"card":4111111111111111}`,     // control
		`{"card":4111111111111111.0}`,   // Python json.dumps(float)
		`{"card":4.111111111111111E15}`, // Java Double.toString / Jackson
		`{"card":4111111111111111e0}`,
		`{"card":4.000000000000000001e18}`,
		`{"card":411111111111111100e-2}`,
	} {
		out, err := s.MaskJSON([]byte(in))
		t.Logf("%s -> %s err=%v", in, out, err)
		if err != nil || string(out) != `{"card":"[REDACTED]"}` {
			t.Errorf("number lexeme not masked as a whole: %s, error=%v", out, err)
		}
	}
	var buf bytes.Buffer
	slog.New(NewSlogHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}), s)).
		Info("refund", "payment", map[string]any{"card": json.Number("4111111111111111.0")})
	t.Logf("slog json.Number: %s", strings.TrimSpace(buf.String()))
	if strings.Contains(buf.String(), "4111111111111111") {
		t.Errorf("json.Number card reached slog output")
	}
}

func TestExactIntegerExpansionBudget(t *testing.T) {
	t.Parallel()
	value, err := exactInteger("1e" + strconv.Itoa(maxEventBytes-1))
	if err != nil || len(value) != maxEventBytes || value[0] != '1' || strings.Trim(value[1:], "0") != "" {
		t.Fatalf("exact expansion budget: length=%d, error=%v", len(value), err)
	}
	if value, err := exactInteger("1e" + strconv.Itoa(maxEventBytes)); err == nil || value != "" {
		t.Fatal("over-budget expansion was accepted")
	}
}

func TestExactIntegerBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input, want string
		failure     bool
	}{
		{"-123.00", "-123", false},
		{"123.00 ", "123", false},
		{"-123e+00\t", "-123", false},
		{exponentWhitespaceString, "0", false},
		{"0.000e100", "0", false},
		{"1.25", "", false},
		{"1e-100", "", false},
		{"1.0e-1000000000", "", false},
		{"1e1000000000", "", true},
		{"1e99999999999999999999", "", true},
		{"100e-2", "1", false},
		{"411111111111111100e-2", "4111111111111111", false},
		{"4.000000000000000001e18", "4000000000000000001", false},
	} {
		got, err := exactInteger(tc.input)
		if got != tc.want || (err != nil) != tc.failure {
			t.Errorf("%s: got %q, %v; want %q, failure=%v", tc.input, got, err, tc.want, tc.failure)
		}
	}
	for _, input := range []string{"1e99999999999999999999", "1e1000000000"} {
		if out, err := NewScanner().MaskJSON([]byte(input)); err == nil || out != nil {
			t.Errorf("unbounded expansion accepted: %q", out)
		}
	}
}

func TestJSONNumberWholeSignedString(t *testing.T) {
	t.Parallel()
	for _, number := range []string{"4111111111111111", "-4111111111111111", "4111111111111111.0", "-4111111111111111e0"} {
		input := []byte(`{"value":"` + number + `"}`)
		got, err := NewScanner().MaskJSON(input)
		if err != nil || string(got) != `{"value":"[REDACTED]"}` {
			t.Fatalf("whole numeric string: %s -> %s (%v)", input, got, err)
		}
	}
}

func TestMaskJSONExponentStringWhitespace(t *testing.T) {
	t.Parallel()
	for _, value := range []string{exponentWhitespaceString, "1e0 ", "-1E+00\t", "0e-00\r\n"} {
		t.Run(strconv.Quote(value), func(t *testing.T) {
			t.Parallel()
			input, err := json.Marshal(map[string]string{budgetPublicKey: value})
			if err != nil {
				t.Fatal(err)
			}
			got, err := NewScanner().MaskJSON(input)
			if err != nil || !bytes.Equal(got, input) {
				t.Fatalf("bounded numeric string: got %s, error=%v; want %s", got, err, input)
			}
		})
	}
}
