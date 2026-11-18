package embargo

import (
	"bytes"
	"log/slog"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// A bitmap oracle avoids repeating Mask's interval sorting and merging.
//
//nolint:gocognit // Keep the independent bitmap and invalid-range oracle in one test.
func TestMaskByteCoverageOracle(t *testing.T) {
	t.Parallel()
	// One invalid range at a time prevents another invalid range from hiding it.
	for position := range 129 {
		text := strings.Repeat("x", 128)
		findings := []Finding{{Kind: KindEmail, Start: position, End: position, Confidence: 1}}
		called := false
		got := MaskFunc(text, findings, func(_ Kind, value string) string {
			called = true
			return value
		})
		if called || got != redactionMarker {
			t.Fatalf("zero-width range at %d did not fail closed before replacement", position)
		}
	}
	rng := rand.New(rand.NewPCG(14, 81)) // #nosec G404 -- Reproducible synthetic test data.
	for trial := range 1000 {
		length := rng.IntN(129)
		original := make([]byte, length)
		for i := range original {
			original[i] = byte(rng.IntN(256)) // #nosec G115 -- IntN(256) fits in one byte.
		}
		covered := make([]bool, length)
		var findings []Finding
		invalid := false
		for range rng.IntN(32) {
			start, end := rng.IntN(length+3)-1, rng.IntN(length+3)-1
			if trial%2 == 0 && length > 0 {
				start = rng.IntN(length)
				end = start + 1 + rng.IntN(length-start)
			}
			findings = append(findings, Finding{Kind: KindEmail, Start: start, End: end, Confidence: 1})
			if start < 0 || end > length || start >= end {
				invalid = true
				continue
			}
			for i := start; i < end; i++ {
				covered[i] = true
			}
		}
		want := bytes.Clone(original)
		for i, hidden := range covered {
			if hidden {
				want[i] = '*'
			}
		}
		if invalid {
			want = []byte(redactionMarker)
		}
		before := slices.Clone(findings)
		for range 2 {
			got := MaskFunc(string(original), findings, func(_ Kind, value string) string { return strings.Repeat("*", len(value)) })
			if got != string(want) {
				t.Fatalf("byte-union oracle disagrees at trial %d", trial)
			}
			if !slices.Equal(findings, before) {
				t.Fatal("masking mutated findings")
			}
			slices.Reverse(findings)
			slices.Reverse(before)
		}
	}
}

func TestMaskUnion(t *testing.T) {
	t.Parallel()
	input := []Finding{{Kind: "a", Start: 1, End: 4, Confidence: .5}, {Kind: "b", Start: 3, End: 6, Confidence: 1}, {Kind: "c", Start: 6, End: 7, Confidence: 1}}
	before := slices.Clone(input)
	if got := Mask("012345678", input); got != "0[REDACTED][REDACTED]78" {
		t.Fatal(got)
	}
	if got := MaskFunc("012345678", input, func(k Kind, v string) string { return string(k) + ":" + v }); got != "0b:12345c:678" {
		t.Fatal(got)
	}
	if !reflect.DeepEqual(input, before) {
		t.Fatal("mutated findings")
	}
	//nolint:goconst // Assert the literal public redaction contract.
	if got := Mask("safe", []Finding{{Start: -1, End: 1}}); got != "[REDACTED]" {
		t.Fatal(got)
	}
	mustPanic(t, func() { MaskFunc("", nil, nil) })
}

func TestMaskKindPreferenceAcrossInputOrder(t *testing.T) {
	t.Parallel()
	findings := []Finding{{Kind: "z-kind", Start: 0, End: 4, Confidence: .9}, {Kind: "a-kind", Start: 1, End: 3, Confidence: .9}}
	for range 2 {
		got := MaskFunc("value!", findings, func(kind Kind, text string) string { return string(kind) + ":" + text })
		if got != "a-kind:value!" {
			t.Fatalf("equal-confidence overlapping kinds selected %q", got)
		}
		slices.Reverse(findings)
	}
}

func lastFour(kind Kind, value string) string {
	if kind != KindPAN {
		return "#" + string(kind) + "#"
	}
	return "****" + value[len(value)-4:]
}

func TestWithMaskFuncReachesRecordsAndJSON(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindPAN, KindEmail), WithMaskFunc(lastFour))
	for input, want := range map[string]string{
		`{"card":"4111111111111111"}`:                    `{"card":"****1111"}`,
		`{"card":4111111111111111}`:                      `{"card":"****1111"}`,
		`{"msg":"paid 4111111111111111 by a@b.example"}`: `{"msg":"paid ****1111 by #email#"}`,
		`{"msg":"paid 4111111111111111"}`:                `{"msg":"paid ****1111"}`,
		`{"4111111111111111":1}`:                         `{"****1111":1}`,
		`{"password":"4111111111111111"}`:                `{"password":"[REDACTED]"}`,
		`{"card":4111111111111111.5}`:                    `{"card":4111111111111111.5}`,
	} {
		got, err := scanner.MaskJSON([]byte(input))
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if string(got) != want {
			t.Errorf("MaskJSON(%s) = %s, want %s", input, got, want)
		}
	}

	var out bytes.Buffer
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: withoutTime}), scanner))
	logger.Info("checkout", "card", int64(4111111111111111), "note", "card 4111111111111111")
	if want := `{"level":"INFO","msg":"checkout","card":"****1111","note":"card ****1111"}` + "\n"; out.String() != want {
		t.Fatalf("slog = %q, want %q", out.String(), want)
	}
}

func TestWithMaskFuncFallsBackToMarker(t *testing.T) {
	t.Parallel()
	echo := NewScanner(WithKinds(KindPAN), WithMaskFunc(func(_ Kind, value string) string { return "<" + value + ">" }))
	if got, err := echo.MaskJSON([]byte(`{"msg":"card 4111111111111111"}`)); err != nil || string(got) != `{"msg":"card [REDACTED]"}` {
		t.Fatalf("a replacement containing the value = %s, %v", got, err)
	}
	partial := NewScanner(WithKinds(KindPAN), WithMaskFunc(lastFour))
	got, err := partial.MaskJSON([]byte(`{"n":4.111111111111111e15}`))
	if err != nil || string(got) != `{"n":"[REDACTED]"}` {
		t.Fatalf("a number only partly covered by a finding = %s, %v", got, err)
	}
	panicking := NewScanner(WithKinds(KindPAN), WithMaskFunc(func(Kind, string) string { panic("boom") }))
	if got, err := panicking.MaskJSON([]byte(`{"msg":"card 4111111111111111"}`)); err == nil || got != nil {
		t.Fatalf("a panicking replacement = %s, %v", got, err)
	}
	var out bytes.Buffer
	slog.New(NewSlogHandler(slog.NewJSONHandler(&out, nil), panicking)).Info("card 4111111111111111")
	if strings.Contains(out.String(), "4111") {
		t.Fatalf("a panicking replacement leaked through slog: %q", out.String())
	}
	defer func() {
		if recover() == nil {
			t.Fatal("WithMaskFunc(nil) did not panic")
		}
	}()
	WithMaskFunc(nil)
}

func withoutTime(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}
