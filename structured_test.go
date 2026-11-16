package embargo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
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
			want := `{"id":"u123","email":"[REDACTED]","password":"[REDACTED]","count":9007199254740993,"enabled":true,"secret_value":"[REDACTED]"}`
			if text {
				if !strings.Contains(got, "user="+strconv.Quote(want)) {
					t.Fatal(got)
				}
				return
			}
			var record map[string]json.RawMessage
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
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
	for _, input := range []string{"\v{}", "{}\f", "\u00a0[]", `{"x":`, `{} {}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66), `"` + strings.Repeat("a", 1<<20) + `"`} {
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
	for _, seed := range []string{`{"password":"opaque","x":["alice@example.com",12]}`, `[1,true,null]`, `"alice@example.com"`, `{"a":1,"a":2}`, `"0@0..AA+@0.AA"`} {
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

func FuzzJSONShape(f *testing.F) {
	for _, seed := range []string{`{"n":9007199254740993,"x":1.0e+5}`, `{"\u0074oken":"visible","array":[true,false,null,-0]}`, `["\uD800","\uD834\uDD1E","a\"b","\\", "\n", "<>&"]`, "{\"x\":\"\xff\"}"} {
		f.Add([]byte(seed))
	}
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithSensitiveKeys())
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := scanner.MaskJSON(data)
		if err != nil {
			return
		}
		decode := func(raw []byte) any {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var result any
			if err := decoder.Decode(&result); err != nil {
				t.Fatal(err)
			}
			return result
		}
		if !reflect.DeepEqual(decode(data), decode(got)) {
			t.Fatal("JSON semantics changed without a masking policy")
		}
	})
}

func TestSensitiveKeysCopyAndValidation(t *testing.T) {
	t.Parallel()
	names := []string{"pin"}
	option := embargo.WithSensitiveKeys(names...)
	names[0] = "other"
	scanner := embargo.NewScanner(embargo.WithKinds(), option)
	got, err := scanner.MaskJSON([]byte(`{"pin":false,"other":"public"}`))
	if err != nil || string(got) != `{"pin":"[REDACTED]","other":"public"}` {
		t.Fatal("option retained caller slice")
	}
	for _, name := range []string{"", "_- ."} {
		func() {
			defer func() {
				if recover() != "embargo: empty sensitive key" {
					t.Error("invalid key panic changed")
				}
			}()
			embargo.WithSensitiveKeys(name)
		}()
	}
	var scannerNil *embargo.Scanner
	if got, err := scannerNil.MaskJSON([]byte(`{}`)); err == nil || got != nil {
		t.Fatal("nil policy accepted")
	}
}

func TestMaskJSONBooleanAndNullContext(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner()
	got, err := scanner.MaskJSON([]byte(`{"client_secret":true,"client_secret":null,"clean":true,"empty":null}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"client_secret":"[REDACTED]","client_secret":"[REDACTED]","clean":true,"empty":null}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestMaskJSONContextStopsBetweenDetectors(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := &cancelingScan{cancel: cancel}
	second := &cancelingScan{cancel: cancel}
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(first), embargo.WithDetector(second))
	safe, err := scanner.MaskJSONContext(ctx, []byte(`{"first":"public","second":"public"}`))
	if err == nil || len(safe) != 0 || first.calls != 1 || second.calls != 0 {
		t.Fatalf("err=%v bytes=%d calls=%d,%d", err, len(safe), first.calls, second.calls)
	}
	safe, err = scanner.MaskJSONContext(ctx, []byte(`"again"`))
	if err == nil || len(safe) != 0 || first.calls != 1 {
		t.Fatal("canceled context started another scan")
	}
}

func TestMaskJSONContextValidationAndZeroValue(t *testing.T) {
	t.Parallel()
	var scanner embargo.Scanner
	safe, err := scanner.MaskJSONContext(t.Context(), []byte(`{"email":"alice@example.com"}`))
	if err != nil || string(safe) != `{"email":"[REDACTED]"}` {
		t.Fatalf("safe=%s err=%v", safe, err)
	}
	var missing context.Context
	safe, err = scanner.MaskJSONContext(missing, []byte(`"public"`))
	if err == nil || len(safe) != 0 {
		t.Fatal("nil context accepted")
	}
}
