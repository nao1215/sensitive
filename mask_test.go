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

// bridgedSpans is an oracle for the spans Mask replaces that does not sort or
// merge intervals: two neighbouring covered bytes belong to one span exactly
// when one finding covers both, so adjacent findings stay separate. It
// returns the text split into public parts and spans, and which are spans.
func bridgedSpans(text string, findings []Finding) (parts []string, hidden []bool) {
	covered := make([]bool, len(text))
	bridged := make([]bool, len(text))
	for _, f := range findings {
		for i := f.Start; i < f.End; i++ {
			covered[i] = true
			bridged[i] = bridged[i] || i > f.Start
		}
	}
	for i := range len(text) {
		if len(parts) == 0 || covered[i] != hidden[len(hidden)-1] || covered[i] && !bridged[i] {
			parts, hidden = append(parts, ""), append(hidden, covered[i])
		}
		parts[len(parts)-1] += text[i : i+1]
	}
	return parts, hidden
}

// bridgedMask joins bridgedSpans with one marker per span.
func bridgedMask(text string, findings []Finding) string {
	parts, hidden := bridgedSpans(text, findings)
	for i := range parts {
		if hidden[i] {
			parts[i] = redactionMarker
		}
	}
	return strings.Join(parts, "")
}

// spanIntervals lists every valid finding range of a text of length n.
func spanIntervals(n int) [][2]int {
	var intervals [][2]int
	for start := range n {
		for end := start + 1; end <= n; end++ {
			intervals = append(intervals, [2]int{start, end})
		}
	}
	return intervals
}

// findingSets lists every sequence of one to limit valid findings over a text
// of length n, so the same ranges also appear in every order.
func findingSets(n, limit int) [][]Finding {
	var sets [][]Finding
	var choose func(findings []Finding)
	choose = func(findings []Finding) {
		if len(findings) > 0 {
			sets = append(sets, findings)
		}
		if len(findings) == limit {
			return
		}
		for _, r := range spanIntervals(n) {
			choose(append(slices.Clip(findings), Finding{Kind: KindEmail, Start: r[0], End: r[1], Confidence: 1}))
		}
	}
	choose(nil)
	return sets
}

// replaceCovered returns text with every byte under a finding changed to a
// different byte taken from replacement.
func replaceCovered(text []byte, findings []Finding, replacement string) []byte {
	replaced := bytes.Clone(text)
	for _, f := range findings {
		for i := f.Start; i < f.End; i++ {
			replaced[i] = replacement[(i+len(findings))%len(replacement)]
			if replaced[i] == text[i] {
				replaced[i]++
			}
		}
	}
	return replaced
}

// TestMaskOutputIgnoresBytesInsideSpans checks every combination of up to
// three valid ranges over texts of up to seven bytes. For fixed findings the
// output depends only on the bytes outside them: replacing every covered byte,
// including with marker text or broken UTF-8, keeps the output, and the output
// matches bridgedMask in either finding order.
func TestMaskOutputIgnoresBytesInsideSpans(t *testing.T) {
	t.Parallel()
	const outside = "ab\xe6\x97\xa5[R]"
	const inside = "[REDACTED]\xff\x00\xe6"
	cases := 0
	for n := range 8 {
		text := []byte(outside + outside)[:n]
		for _, findings := range findingSets(n, 3) {
			cases++
			replaced := string(replaceCovered(text, findings, inside))
			reversed := slices.Clone(findings)
			slices.Reverse(reversed)
			want := bridgedMask(string(text), findings)
			for _, got := range []string{Mask(string(text), findings), Mask(replaced, findings), Mask(replaced, reversed)} {
				if got != want {
					t.Fatalf("Mask(%q, %v) = %q, want %q", replaced, findings, got, want)
				}
			}
		}
	}
	if cases != 37512 {
		t.Fatalf("enumerated %d finding sets", cases)
	}
}

// TestMaskFuncPassesEachMergedSpanOnce checks that the callback sees exactly
// the bytes of each merged span, once and in input order, and nothing else.
// A callback that ignores its value therefore keeps the Mask guarantee; one
// that returns part of the value discloses that part.
func TestMaskFuncPassesEachMergedSpanOnce(t *testing.T) {
	t.Parallel()
	text := "0123456789"
	for _, a := range spanIntervals(len(text)) {
		for _, b := range spanIntervals(len(text)) {
			findings := []Finding{{Kind: KindEmail, Start: a[0], End: a[1], Confidence: 1}, {Kind: KindPAN, Start: b[0], End: b[1], Confidence: 1}}
			var values []string
			got := MaskFunc(text, findings, func(_ Kind, value string) string {
				values = append(values, value)
				return "<" + value + ">"
			})
			parts, hidden := bridgedSpans(text, findings)
			var want []string
			for i, part := range parts {
				if hidden[i] {
					want = append(want, part)
					parts[i] = "<" + part + ">"
				}
			}
			if !slices.Equal(values, want) || got != strings.Join(parts, "") {
				t.Fatalf("%v: callback saw %q and returned %q", findings, values, got)
			}
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
		`{"email":"a@b.example"}`:                        `{"email":"#email#"}`,
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

func TestMaskJSONMarksSpansThatTouchOneEnd(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail))
	for input, want := range map[string]string{
		`{"msg":"mail a@b.example"}`: `{"msg":"mail [REDACTED]"}`,
		`{"msg":"a@b.example ok"}`:   `{"msg":"[REDACTED] ok"}`,
		`{"msg":"a@b.example"}`:      `{"msg":"[REDACTED]"}`,
	} {
		if got, err := scanner.MaskJSON([]byte(input)); err != nil || string(got) != want {
			t.Errorf("MaskJSON(%s) = %s, %v; want %s", input, got, err, want)
		}
	}
}
