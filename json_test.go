package embargo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nao1215/embargo/internal/saferecord"
)

type cancelingScan struct {
	cancel context.CancelFunc
	calls  int
}

func (d *cancelingScan) Scan([]byte) []Finding { d.calls++; d.cancel(); return nil }

type generatedJSON struct{}

func (generatedJSON) MarshalJSON() ([]byte, error) {
	return []byte(`{"email":"alice@example.com","count":17}`), nil
}

//nolint:govet // Preserve JSON field order in this encoding contract fixture.
type jsonShape struct {
	ID          string         `json:"id"`
	Email       string         `json:"email"`
	Hidden      string         `json:"-"`
	Empty       string         `json:"empty,omitempty"`
	Password    string         `json:"password"`
	Count       json.Number    `json:"count"`
	Enabled     bool           `json:"enabled"`
	SecretValue Secret[string] `json:"secret_value"`
	private     string
}

//nolint:goconst // Keep each leak fixture visible beside its expected JSON.
func TestStructuredSlogKeepsJSONShape(t *testing.T) {
	t.Parallel()
	// #nosec G101 -- Synthetic password fixture; this test proves it never reaches the sink.
	value := jsonShape{ID: "u123", Email: "alice@example.com", Hidden: "never", Password: "opaque-value", Count: "9007199254740993", Enabled: true, SecretValue: NewSecret("opaque-secret"), private: "never"}
	for _, text := range []bool{false, true} {
		t.Run(strconv.FormatBool(text), func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			var next slog.Handler = slog.NewJSONHandler(&out, nil)
			if text {
				next = slog.NewTextHandler(&out, nil)
			}
			logger := slog.New(NewSlogHandler(next, NewScanner(WithKinds(KindEmail))))
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
		opts              []ScannerOption
	}{
		{name: "defaults and duplicate keys", input: `{"API_key":"x","apiKey":42,"Authorization":{"a":"b"},"Password":null,"Set-Cookie":["x"],"email":"alice@example.com","n":1.20,"ok":true,"x":1,"x":2}`, want: `{"API_key":"[REDACTED]","apiKey":"[REDACTED]","Authorization":"[REDACTED]","Password":"[REDACTED]","Set-Cookie":"[REDACTED]","email":"[REDACTED]","n":1.20,"ok":true,"x":1,"x":2}`},
		{name: "replace", input: `{"password":"public","PIN":"opaque"}`, want: `{"password":"public","PIN":"[REDACTED]"}`, opts: []ScannerOption{WithSensitiveKeys("pin")}},
		{name: "disable", input: `{"password":"public"}`, want: `{"password":"public"}`, opts: []ScannerOption{WithSensitiveKeys()}},
		{name: "array", input: `[{"token":"x"},"alice@example.com",null,19]`, want: `[{"token":"[REDACTED]"},"[REDACTED]",null,19]`},
		{name: "keys", input: `{"alice@example.com":"ok"}`, want: `{"[REDACTED]":"ok"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scanner := NewScanner(append([]ScannerOption{WithKinds(KindEmail)}, tc.opts...)...)
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
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&out, nil), NewScanner(WithKinds())))
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
	scanner := NewScanner()
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
	slog.New(NewSlogHandler(slog.NewJSONHandler(&out, nil), NewScanner(WithKinds(KindEmail)))).Info("request", "data", value)
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
		handler := NewSlogHandler(slog.NewJSONHandler(&out, nil), NewScanner())
		// RawMessage and containers go through the bounded JSON path.
		record := slog.NewRecord(time.Time{}, slog.LevelInfo, "request", 0)
		record.AddAttrs(slog.Any("data", []any{value}))
		if err := handler.Handle(t.Context(), record); err == nil || !strings.Contains(out.String(), "record withheld") {
			t.Fatal("invalid structured data reached sink")
		}
	}
	for _, key := range []string{"authorization", "ordinary"} {
		input := `{"` + key + `":` + strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64) + "}"
		if data, err := NewScanner().MaskJSON([]byte(input)); err == nil || data != nil {
			t.Fatal("hidden and visible values must share the depth limit")
		}
	}
}

func FuzzMaskJSON(f *testing.F) {
	for _, seed := range []string{`{"password":"opaque","x":["alice@example.com",12]}`, `[1,true,null]`, `"alice@example.com"`, `{"a":1,"a":2}`, `"0@0..AA+@0.AA"`} {
		f.Add([]byte(seed))
	}
	scanner := NewScanner(WithKinds(KindEmail))
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
	scanner := NewScanner(WithKinds(), WithSensitiveKeys())
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
	option := WithSensitiveKeys(names...)
	names[0] = "other"
	scanner := NewScanner(WithKinds(), option)
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
			WithSensitiveKeys(name)
		}()
	}
	var scannerNil *Scanner
	if got, err := scannerNil.MaskJSON([]byte(`{}`)); err == nil || got != nil {
		t.Fatal("nil policy accepted")
	}
}

func TestMaskJSONBooleanAndNullContext(t *testing.T) {
	t.Parallel()
	scanner := NewScanner()
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
	scanner := NewScanner(WithKinds(), WithDetector(first), WithDetector(second))
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
	var scanner Scanner
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

type measuredJSONDetector struct{ bytes int }

func (d *measuredJSONDetector) Scan(data []byte) []Finding { d.bytes += len(data); return nil }

const (
	nestedPercentPrefix = "%252525"
	digitSeparatorRun   = "9 - "
	ibanPrefixRun       = "DE00 "
	credentialPrefixRun = "password="
)

// These cases define the encoding boundary, including unsupported disguises.
func TestAdversarialEncodingBoundary(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	for _, tc := range []struct {
		name, text string
		caught     bool
	}{
		{"plain", "alice@example.com", true},
		{"percent", "alice%40example.com", true},
		{"double-percent", "alice%2540example.com", false},
		{"base64", "YWxpY2VAZXhhbXBsZS5jb20=", false},
		{"zero-width", "alice@exam\u200bple.com", true},
		{"homoglyph", "alice＠example.com", false},
		{"forged-marker", "[REDACTED] alice@example.com", true},
		{"fake-finding", "{Kind:email Start:0 End:99} alice@example.com", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := scanner.ScanString(tc.text); (len(got) > 0) != tc.caught {
				t.Fatal("documented encoding boundary changed")
			}
		})
	}
	masked, err := scanner.MaskJSON([]byte(`{"value":"alice\u0040example.com"}`))
	if err != nil || bytes.Contains(masked, []byte("alice")) {
		t.Fatal("JSON escape bypass")
	}
	// An attacker-controlled audit ID may be masked even when it is not PII.
	scoped := NewScanner(WithKinds(), WithSensitiveKeys("password"))
	document := []byte(`{"audit_id":"alice@example.com","password":"opaque-value"}`)
	masked, err = scoped.MaskJSON(document)
	if err != nil || !bytes.Contains(masked, []byte("alice@example.com")) || bytes.Contains(masked, []byte("opaque-value")) {
		t.Fatal("scoped policy lost audit field or exposed declared secret")
	}
}

func TestAdversarialJSONLimits(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithAll())
	for _, depth := range []int{63, 64, 65, 10000} {
		input := []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
		out, err := scanner.MaskJSON(input)
		if depth <= 64 {
			if err != nil || !json.Valid(out) {
				t.Fatal("valid bounded tree rejected")
			}
		} else if out != nil || err == nil || err.Error() != "embargo: JSON size limit exceeded" {
			t.Fatal("deep tree did not fail closed")
		}
	}
	for _, size := range []int{1 << 20, 16 << 20} {
		input := []byte(`{"value":"` + strings.Repeat("x", size) + `"}`)
		out, err := scanner.MaskJSON(input)
		if out != nil || err == nil {
			t.Fatal("oversized document accepted")
		}
	}
	wide := []byte("[" + strings.Repeat(`{"password":"opaque","count":1},`, 1000) + "null]")
	out, err := scanner.MaskJSON(wide)
	if err != nil || !json.Valid(out) || bytes.Contains(out, []byte("opaque")) || bytes.Count(out, []byte(`"count":1`)) != 1000 {
		t.Fatal("wide JSON lost public fields or retained a secret")
	}
}

//nolint:paralleltest // Process-wide allocation accounting must run without concurrent tests.
func TestAdversarialAllocationBudget(t *testing.T) {
	for _, pattern := range []string{digitSeparatorRun, credentialPrefixRun, nestedPercentPrefix, ibanPrefixRun, "=== RUN   fake\n"} {
		data := []byte(strings.Repeat(pattern, (64<<10)/len(pattern)))
		for _, detector := range builtins(nil) {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			detector.Scan(data)
			runtime.ReadMemStats(&after)
			if after.TotalAlloc-before.TotalAlloc > uint64(len(data))*128+1<<20 {
				t.Fatalf("allocation amplification in %s", detector.Name())
			}
		}
	}
}

// Scheduled measurements cover every detector and the public output boundaries.
// Times are reported, while deterministic allocation properties are hard gates.
//
//nolint:gocognit // Keep the same matrix inputs visible across all public paths.
func BenchmarkAdversarialScaling(b *testing.B) {
	b.Run("MaskDense", benchmarkAdversarialMaskRanges)
	b.Run("SharedSuffix", benchmarkSharedSuffix)
	for _, pattern := range []string{digitSeparatorRun, credentialPrefixRun, nestedPercentPrefix, "DE00 "} {
		for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
			data := []byte(strings.Repeat(pattern, size/len(pattern)))
			scanners := map[string]*Scanner{"all": NewScanner(WithAll())}
			for _, detector := range builtins(nil) {
				scanners[string(detector.Name())] = NewScanner(WithKinds(Kind(detector.Name())))
			}
			for name, scanner := range scanners {
				b.Run(fmt.Sprintf("%s/%s/%d", name, pattern, size), func(b *testing.B) {
					b.SetBytes(int64(len(data)))
					b.ReportAllocs()
					for b.Loop() {
						scanner.Scan(data)
					}
				})
			}
			scanner := scanners["all"]
			b.Run(fmt.Sprintf("Mask/%s/%d", pattern, size), func(b *testing.B) {
				text := string(data)
				findings := scanner.Scan(data)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					Mask(text, findings)
				}
			})
			b.Run(fmt.Sprintf("MaskJSON/%s/%d", pattern, size), func(b *testing.B) {
				document, err := json.Marshal(string(data))
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if _, err := scanner.MaskJSON(document); err != nil && len(document) <= maxEventBytes {
						b.Fatal(err)
					}
				}
			})
			b.Run(fmt.Sprintf("slog/%s/%d", pattern, size), func(b *testing.B) {
				//nolint:sloglint // This benchmark must include JSON encoding.
				handler := NewSlogHandler(slog.NewJSONHandler(io.Discard, nil), scanner)
				record := slog.Record{Message: string(data)}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if err := handler.Handle(context.Background(), record); err != nil && len(data) < maxEventBytes/2 {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// Empty finding slices do not exercise copying, sorting or range replacement.
func benchmarkAdversarialMaskRanges(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
		text := strings.Repeat("x", size)
		findings := make([]Finding, 0, size/32)
		for start := 0; start+8 <= size; start += 32 {
			findings = append(findings, Finding{Kind: KindEmail, Start: start, End: start + 8, Confidence: 1})
		}
		for _, order := range []string{"forward", "reverse"} {
			if order == "reverse" {
				slices.Reverse(findings)
			}
			b.Run(fmt.Sprintf("%s/%d", order, size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					Mask(text, findings)
				}
			})
		}
	}
}

func TestJSONExpansionStopsBeforeRetainingPastLimit(t *testing.T) {
	t.Parallel()
	input := []byte("[" + strings.Repeat(`"x",`, 100000) + `"x"]`)
	scanner := NewScanner(WithKinds(), WithSensitiveKeys(), WithDetector(expandingDetector{}))
	walker := jsonWalker{data: input, scanner: eventScanner{scanner: scanner, remaining: maxScanBytes}}
	if err := walker.value(t.Context(), 0, "", false); err == nil {
		t.Fatal("expanded output accepted")
	}
	if len(walker.result) > maxEventBytes {
		t.Fatalf("retained %d bytes past output limit", len(walker.result))
	}
}

type expandingDetector struct{}

func (expandingDetector) Scan(data []byte) []Finding {
	if string(data) == "x" {
		return []Finding{{Kind: "synthetic", Start: 0, End: 1, Confidence: 1}}
	}
	return nil
}

func BenchmarkJSONExpansionLimit(b *testing.B) {
	input := []byte("[" + strings.Repeat(`"x",`, 100000) + `"x"]`)
	scanner := NewScanner(WithKinds(), WithSensitiveKeys(), WithDetector(expandingDetector{}))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := scanner.MaskJSON(input); err == nil {
			b.Fatal("expanded output accepted")
		}
	}
}

func sharedSuffixInputs() []struct {
	kind         Kind
	unit, suffix string
} {
	const hostname = "example.invalid"
	return []struct {
		kind         Kind
		unit, suffix string
	}{
		{KindPAN, "4111111111111112-node-", hostname},
		{KindJPPhone, "09012345678-node-", hostname},
		{KindMyNumber, "123456789018-node-", hostname},
		{KindGitHubToken, "xgithub_pat_", ""},
		{KindSlackToken, "xxoxb-", ""},
	}
}

func benchmarkSharedSuffix(b *testing.B) {
	for _, tc := range sharedSuffixInputs() {
		for _, count := range []int{1024, 2048, 4096, 8192} {
			b.Run(fmt.Sprintf("%s/%d", tc.kind, count), func(b *testing.B) {
				scanner := NewScanner(WithKinds(tc.kind))
				data := []byte(strings.Repeat(tc.unit, count) + tc.suffix)
				if got := scanner.Scan(data); len(got) != 0 {
					b.Fatalf("unexpected findings: %v", got)
				}
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					scanner.Scan(data)
				}
			})
		}
	}
}

//nolint:paralleltest // Compare scaling without overlapping other test workloads.
func TestAdversarialSharedSuffixScaling(t *testing.T) {
	for _, tc := range sharedSuffixInputs() {
		t.Run(string(tc.kind), func(t *testing.T) {
			scanner := NewScanner(WithKinds(tc.kind))
			measure := func(count int) time.Duration {
				data := []byte(strings.Repeat(tc.unit, count) + tc.suffix)
				best := time.Hour
				for range 3 {
					start := time.Now()
					calls := 0
					var elapsed time.Duration
					// Batch beyond coarse platform clocks before comparing per-call costs.
					for elapsed < 20*time.Millisecond {
						if got := scanner.Scan(data); len(got) != 0 {
							t.Fatalf("unexpected findings: %v", got)
						}
						calls++
						elapsed = time.Since(start)
					}
					best = min(best, elapsed/time.Duration(calls))
				}
				return best
			}
			small, large := measure(256), measure(4096)
			t.Logf("small=%s large=%s ratio=%.2f", small, large, float64(large)/float64(small))
			// Sixteen times the input permits four times linear cost, but not quadratic growth.
			if large > 64*small+time.Millisecond {
				t.Fatal("shared suffix scanning is superlinear")
			}
		})
	}
}

func TestJSONJoinedKeyPaths(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"alice@example":{"com":"x"}}`,
		`{"10":{"20":{"30":{"40":"x"}}}}`,
		`{"alice@example":[{"com":1},{"com":2}],"safe":3}`,
		`{"alice@example":{"com":1},"alice@example":{"com":2}}`,
	} {
		got, err := NewScanner().MaskJSON([]byte(input))
		if err != nil || !json.Valid(got) || bytes.Contains(got, []byte("alice@example")) || bytes.Contains(got, []byte(`"com"`)) || bytes.Contains(got, []byte(`"10"`)) || bytes.Contains(got, []byte(`"20"`)) || bytes.Contains(got, []byte(`"30"`)) || bytes.Contains(got, []byte(`"40"`)) {
			t.Errorf("path: %s => %s (%v)", input, got, err)
		}
	}
}

func TestWalkerFailureBoundaries(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	walker := jsonWalker{data: []byte(`[]`), scanner: eventScanner{scanner: NewScanner(), remaining: maxScanBytes}}
	if err := walker.value(ctx, 0, "", false); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatal("canceled walk accepted")
	}
	walker.err = saferecord.ErrSizeLimit
	if err := walker.value(t.Context(), 0, "", false); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("sticky walk failure cleared")
	}
	walker.appendResult([]byte("private"))
	if walker.result != nil {
		t.Fatal("failed walker retained output")
	}
	walker.err = nil
	walker.result = bytes.Repeat([]byte("x"), maxEventBytes)
	if err := walker.container(t.Context(), 0, "", false); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("container expansion exceeded budget")
	}
	scanner := eventScanner{scanner: NewScanner(), remaining: 1}
	if _, err := scanner.joinedKeySensitive(t.Context(), "a.b", 1); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("joined path exceeded scan budget")
	}
	scanner.remaining = maxScanBytes
	if _, err := scanner.joinedKeySensitive(ctx, "a.b", 1); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatal("canceled joined path accepted")
	}
	if _, err := scanner.scanScalar(ctx, "private", ""); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatal("canceled scalar accepted")
	}
	scanner.remaining = len("1.0e0")
	if _, err := scanner.maskScalar(t.Context(), "1.0e0", ""); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("canonical number scan escaped budget")
	}
	walker = jsonWalker{path: []jsonKeyPosition{{path: "a"}}, scanner: eventScanner{scanner: NewScanner(), remaining: 1}}
	if err := walker.keyPath(t.Context(), "b", 0, 3); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("path error did not propagate")
	}
}

func TestJoinedJSONOutputExpansionIsBounded(t *testing.T) {
	t.Parallel()
	suffix := `","1":{"2":{"3":{"4":0}}}}`
	input := `{"padding":"` + strings.Repeat("x", maxEventBytes-len(`{"padding":"`)-len(suffix)) + suffix
	masked, err := NewScanner(WithKinds(KindIPAddr)).MaskJSON([]byte(input))
	if !errors.Is(err, saferecord.ErrSizeLimit) || masked != nil {
		t.Fatal("joined key replacement exceeded output budget", err)
	}
}

type jsonPanicDetector struct{}

func (jsonPanicDetector) Scan([]byte) []Finding { panic("private detector failure") }

func TestJSONDetectorPanicReturnsNoPartialDocument(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(), WithDetector(jsonPanicDetector{}))
	got, err := scanner.MaskJSON([]byte(`{"public":true,"secret":"private"}`))
	if !errors.Is(err, saferecord.ErrMasking) || got != nil || strings.Contains(err.Error(), "private") {
		t.Fatal("detector panic exposed a partial document")
	}
}

func TestMaskJSONFixedFailureReasons(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		want     string
		data     []byte
		canceled bool
	}{
		{"embargo: invalid or unmaskable JSON", []byte(`{"password":"opaqueFixture"`), false},
		{"embargo: JSON size limit exceeded", []byte(`"` + strings.Repeat("opaqueFixture", 100000) + `"`), false},
		{"embargo: JSON masking canceled", []byte(`{"password":"opaqueFixture"}`), true},
	} {
		ctx, cancel := context.WithCancel(t.Context())
		if tc.canceled {
			cancel()
		}
		got, err := NewScanner().MaskJSONContext(ctx, tc.data)
		cancel()
		if got != nil || err == nil || err.Error() != tc.want {
			t.Errorf("got=%q err=%v want=%q", got, err, tc.want)
		}
	}
}

func TestPlainJSONTextMatchesEncodingJSON(t *testing.T) {
	t.Parallel()
	for b := range 256 {
		text := "a" + string([]byte{byte(b)}) + "z"
		encoded, err := json.Marshal(any(text))
		if err != nil {
			t.Fatal(err)
		}
		plain := string(encoded) == `"`+text+`"`
		if got := plainJSONText(text); got && !plain {
			t.Errorf("byte %#x: plainJSONText is true but encoding/json writes %s", b, encoded)
		} else if got != plain && b < utf8.RuneSelf {
			t.Errorf("byte %#x: plainJSONText = %v, encoding/json unchanged = %v", b, got, plain)
		}
	}
	for _, text := range []string{"", redactionMarker, "user " + redactionMarker + " failed", "é", " "} {
		walker := jsonWalker{}
		walker.appendString(text)
		want, err := json.Marshal(any(text))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(walker.result, want) {
			t.Errorf("appendString(%q) = %s, want %s", text, walker.result, want)
		}
	}
	full := jsonWalker{result: make([]byte, maxEventBytes-len(`"ab"`)+1)}
	full.appendString("ab")
	if !errors.Is(full.err, saferecord.ErrSizeLimit) || len(full.result) != maxEventBytes-len(`"ab"`)+1 {
		t.Fatalf("appendString past the limit: err %v, length %d", full.err, len(full.result))
	}
	exact := jsonWalker{result: make([]byte, maxEventBytes-len(`"ab"`))}
	exact.appendString("ab")
	if exact.err != nil || len(exact.result) != maxEventBytes {
		t.Fatalf("appendString at the limit: err %v, length %d", exact.err, len(exact.result))
	}
}

func TestJSONFastPathsStopOnBudgetCancellationAndOutputLimit(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	warm := eventScanner{scanner: scanner, remaining: maxScanBytes}
	if _, err := warm.maskCached(t.Context(), "status"); err != nil {
		t.Fatal(err)
	}
	walker := func(remaining int, result []byte) *jsonWalker {
		return &jsonWalker{data: nil, result: result, scanner: eventScanner{scanner: scanner, remaining: remaining}}
	}
	// A cached key still pays its budget, so an exhausted budget stops the key.
	if _, err := walker(len("status")-1, nil).objectKey(t.Context(), []byte(`"status"`)); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatalf("cached key beyond the budget: %v", err)
	}
	// A cached key that would overflow the output stops before it is copied.
	full := walker(maxScanBytes, make([]byte, maxEventBytes-len(`"status"`)+1))
	if _, err := full.objectKey(t.Context(), []byte(`"status"`)); !errors.Is(err, saferecord.ErrSizeLimit) || len(full.result) != maxEventBytes-len(`"status"`)+1 {
		t.Fatalf("cached key past the output limit: %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := walker(maxScanBytes, nil).stringElement(canceled, []byte(`"plain value"`), "note"); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatalf("plain string after cancellation: %v", err)
	}
}
