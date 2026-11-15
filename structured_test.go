package embargo_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/embargo"
)

type generatedJSON struct{}

func (generatedJSON) MarshalJSON() ([]byte, error) {
	return []byte(`{"email":"alice@example.com","count":17}`), nil
}

//nolint:govet // Preserve JSON field order in this encoding contract fixture.
type jsonShape struct {
	ID          string                 `json:"id"`
	Email       string                 `json:"email"`
	Hidden      string                 `json:"-"`
	Empty       string                 `json:"empty,omitempty"`
	Password    string                 `json:"password"`
	Count       json.Number            `json:"count"`
	Enabled     bool                   `json:"enabled"`
	SecretValue embargo.Secret[string] `json:"secret_value"`
	private     string
}

//nolint:goconst // Keep each leak fixture visible beside its expected JSON.
func TestStructuredSlogKeepsJSONShape(t *testing.T) {
	t.Parallel()
	// #nosec G101 -- Synthetic password fixture; this test proves it never reaches the sink.
	value := jsonShape{ID: "u123", Email: "alice@example.com", Hidden: "never", Password: "opaque-value", Count: "9007199254740993", Enabled: true, SecretValue: embargo.NewSecret("opaque-secret"), private: "never"}
	for _, text := range []bool{false, true} {
		t.Run(strconv.FormatBool(text), func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			var next slog.Handler = slog.NewJSONHandler(&out, nil)
			if text {
				next = slog.NewTextHandler(&out, nil)
			}
			logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))))
			logger.Info("request", "user", value, "custom", generatedJSON{}, "error", fmt.Errorf("failed: %w", errors.New("alice@example.com")))
			got := out.String()
			for _, leak := range []string{"alice@example.com", "opaque-value", "opaque-secret", "never"} {
				if strings.Contains(got, leak) {
					t.Fatalf("leak: %s", got)
				}
			}
			if text {
				if !strings.Contains(got, `9007199254740993`) {
					t.Fatal(got)
				}
				return
			}
			var record map[string]json.RawMessage
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			want := `{"id":"u123","email":"[REDACTED]","password":"[REDACTED]","count":9007199254740993,"enabled":true,"secret_value":"[REDACTED]"}`
			if string(record["user"]) != want {
				t.Fatalf("got %s want %s", record["user"], want)
			}
			if string(record["custom"]) != `{"email":"[REDACTED]","count":17}` || string(record["error"]) != `"failed: [REDACTED]"` {
				t.Fatal(got)
			}
		})
	}
}

func TestMaskJSONKeyPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, input, want string
		opts              []embargo.ScannerOption
	}{
		{name: "defaults and duplicate keys", input: `{"API_key":"x","apiKey":42,"Authorization":{"a":"b"},"Password":null,"Set-Cookie":["x"],"email":"alice@example.com","n":1.20,"ok":true,"x":1,"x":2}`, want: `{"API_key":"[REDACTED]","apiKey":"[REDACTED]","Authorization":"[REDACTED]","Password":"[REDACTED]","Set-Cookie":"[REDACTED]","email":"[REDACTED]","n":1.20,"ok":true,"x":1,"x":2}`},
		{name: "replace", input: `{"password":"public","PIN":"opaque"}`, want: `{"password":"public","PIN":"[REDACTED]"}`, opts: []embargo.ScannerOption{embargo.WithSensitiveKeys("pin")}},
		{name: "disable", input: `{"password":"public"}`, want: `{"password":"public"}`, opts: []embargo.ScannerOption{embargo.WithSensitiveKeys()}},
		{name: "array", input: `[{"token":"x"},"alice@example.com",null,19]`, want: `[{"token":"[REDACTED]"},"[REDACTED]",null,19]`},
		{name: "keys", input: `{"alice@example.com":"ok"}`, want: `{"[REDACTED]":"ok"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scanner := embargo.NewScanner(append([]embargo.ScannerOption{embargo.WithKinds(embargo.KindEmail)}, tc.opts...)...)
			got, err := scanner.MaskJSON([]byte(tc.input))
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %s err %v want %s", got, err, tc.want)
			}
		})
	}
}

func TestSensitiveSlogGroups(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), embargo.NewScanner(embargo.WithKinds())))
	logger.With("password", "attached").WithGroup("outer").With("ok", 7).WithGroup("api-key").With("x", "hidden").WithGroup("nested").Info("request", "x", "hidden")
	logger.Info("request", slog.Group("token", slog.String("x", "hidden")))
	if strings.Contains(out.String(), "hidden") || strings.Contains(out.String(), "attached") {
		t.Fatal(out.String())
	}
	if !strings.Contains(out.String(), `"api-key":"[REDACTED]"`) || !strings.Contains(out.String(), `"token":"[REDACTED]"`) {
		t.Fatal(out.String())
	}
}

func TestMaskJSONFailureBounds(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner()
	for _, input := range []string{`{"x":`, `{} {}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66), `"` + strings.Repeat("a", 1<<20) + `"`} {
		got, err := scanner.MaskJSON([]byte(input))
		if err == nil || got != nil || strings.Contains(err.Error(), input) {
			t.Fatal("invalid JSON accepted or error reflected input")
		}
	}
}

type nestedLogValue struct {
	Email string `json:"email"`
}

func (nestedLogValue) LogValue() slog.Value {
	return slog.StringValue("a different log representation")
}

func TestNestedLogValuerFollowsJSONHandler(t *testing.T) {
	t.Parallel()
	value := struct {
		Nested nestedLogValue `json:"nested"`
	}{nestedLogValue{"alice@example.com"}}
	var out bytes.Buffer
	slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), embargo.NewScanner(embargo.WithKinds(embargo.KindEmail)))).Info("request", "data", value)
	if !strings.Contains(out.String(), `"data":{"nested":{"email":"[REDACTED]"}}`) {
		t.Fatal(out.String())
	}
}

func TestStructuredFailuresNeverForward(t *testing.T) {
	t.Parallel()
	cycle := map[string]any{}
	cycle["cycle"] = cycle
	for _, value := range []any{cycle, strings.Repeat("x", 1<<20), json.RawMessage(`{"x":`), json.RawMessage(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66))} {
		var out bytes.Buffer
		handler := embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), embargo.NewScanner())
		// RawMessage and containers go through the bounded JSON path.
		record := slog.NewRecord(time.Time{}, slog.LevelInfo, "request", 0)
		record.AddAttrs(slog.Any("data", []any{value}))
		if err := handler.Handle(t.Context(), record); err == nil || out.Len() != 0 {
			t.Fatal("invalid structured data reached sink")
		}
	}
	for _, key := range []string{"authorization", "ordinary"} {
		input := `{"` + key + `":` + strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64) + "}"
		if data, err := embargo.NewScanner().MaskJSON([]byte(input)); err == nil || data != nil {
			t.Fatal("hidden and visible values must share the depth limit")
		}
	}
}

func FuzzMaskJSON(f *testing.F) {
	for _, seed := range []string{`{"password":"opaque","x":["alice@example.com",12]}`, `[1,true,null]`, `"alice@example.com"`, `{"a":1,"a":2}`} {
		f.Add([]byte(seed))
	}
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	f.Fuzz(func(t *testing.T, data []byte) {
		original := bytes.Clone(data)
		got, err := scanner.MaskJSON(data)
		if !bytes.Equal(data, original) {
			t.Fatal("input mutated")
		}
		if err != nil {
			if got != nil {
				t.Fatal("partial result")
			}
			return
		}
		if !json.Valid(got) {
			t.Fatal("invalid output")
		}
		again, err := scanner.MaskJSON(got)
		if err != nil || !bytes.Equal(got, again) {
			t.Fatal("masking should be idempotent")
		}
	})
}
