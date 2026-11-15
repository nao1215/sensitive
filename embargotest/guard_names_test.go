package embargotest

import (
	"slices"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestGuardNamesAtLeak(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, frames, want string }{
		{"completed peer", "=== RUN   TestDone\n--- PASS: TestDone (0.00s)\n=== RUN   TestParent\n=== RUN   TestParent/child\n", "TestParent, TestParent/child"},
		{"paused peer", "=== RUN   TestPaused\n=== PAUSE TestPaused\n=== RUN   TestLive\n", "TestLive"},
		{"resumed peer", "=== RUN   TestLive\n=== PAUSE TestLive\n=== CONT  TestLive\n", "TestLive"},
		{"no frames", "", "[unavailable]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := []byte(tc.frames + defaultCanary + "\n--- PASS: TestLive (0.00s)\n=== RUN   TestLater\n")
			capture := &guardCapture{data: [2][]byte{data, nil}}
			got := guardTests(capture, 0, []embargo.Finding{{Start: len(tc.frames), End: len(tc.frames) + len(defaultCanary)}}, guardPolicy(nil))
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGuardNameValidation(t *testing.T) {
	t.Parallel()
	policy := guardPolicy(nil)
	const redacted = "[redacted test name]"
	for _, tc := range []struct{ name, want string }{
		{"Test名前/size=3,ok -._", "Test名前/size=3,ok -._"},
		{strings.Repeat("x", 120), strings.Repeat("x", 120)},
		{strings.Repeat("x", 121), redacted},
		{"bad\x1b[31m", redacted},
		{"bad@name", redacted},
		{"", redacted},
		{defaultCanary, redacted},
		{"guard@example.com", redacted},
		{"password=opaque", redacted},
		{"opaque-private-value-not-known-to-detectors", "opaque-private-value-not-known-to-detectors"},
	} {
		if got := guardSafeName(tc.name, policy); got != tc.want {
			t.Fatalf("name validation: got %q, want %q", got, tc.want)
		}
	}
	policy.scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(&panickingGuardDetector{}))
	if got := guardSafeName("TestSafe", policy); got != redacted {
		t.Fatal("scanner failure exposed a name")
	}
}

func TestGuardStderrUsesObservedActiveNames(t *testing.T) {
	t.Parallel()
	capture := &guardCapture{maxBytes: 4096}
	stdout := &guardStream{capture: capture, index: 0}
	stderr := &guardStream{capture: capture, index: 1}
	for _, entry := range []struct {
		stream *guardStream
		data   string
	}{
		{stdout, "=== RUN   TestDuring\n"},
		{stderr, defaultCanary},
		{stdout, "--- PASS: TestDuring (0.00s)\n=== RUN   TestLater\n"},
	} {
		if _, err := entry.stream.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	got := guardTests(capture, 1, []embargo.Finding{{Start: 0, End: len(defaultCanary)}}, guardPolicy(nil))
	if got != "TestDuring" {
		t.Fatal(got)
	}
}

func TestGuardCanaryRangesCoverRepeatedAndFinalBytes(t *testing.T) {
	t.Parallel()
	policy := guardPolicy([]Option{WithScanner(embargo.NewScanner(embargo.WithKinds()))})
	policy.needles = [][]byte{[]byte("canary")}
	findings, failed := guardLeaks([]byte("_canarycanary"), policy)
	want := []embargo.Finding{{Start: 1, End: 7}, {Start: 7, End: 13}}
	if failed || !slices.Equal(findings, want) {
		t.Fatalf("got %v, failed %v", findings, failed)
	}
}

func TestGuardBlankLinesDoNotHideLaterFrames(t *testing.T) {
	t.Parallel()
	data := []byte("\n=== RUN   TestAfterBlank\nleak")
	capture := &guardCapture{data: [2][]byte{data, nil}}
	got := guardTests(capture, 0, []embargo.Finding{{Start: len(data) - 4, End: len(data)}}, guardPolicy(nil))
	if got != "TestAfterBlank" {
		t.Fatal(got)
	}
}

func TestGuardFrameEndingAtLeakIsNotYetComplete(t *testing.T) {
	t.Parallel()
	data := []byte("=== RUN   TestBeforeNewline\n")
	capture := &guardCapture{data: [2][]byte{data, nil}}
	got := guardTests(capture, 0, []embargo.Finding{{Start: len(data) - 1, End: len(data)}}, guardPolicy(nil))
	if got != "[unavailable]" {
		t.Fatal(got)
	}
}

func TestGuardStderrExcludesAdjacentCleanWrites(t *testing.T) {
	t.Parallel()
	capture := &guardCapture{maxBytes: 4096}
	stdout := &guardStream{capture: capture, index: 0}
	stderr := &guardStream{capture: capture, index: 1}
	for _, entry := range []struct {
		stream *guardStream
		data   string
	}{
		{stdout, "=== RUN   TestBefore\n"},
		{stderr, "ping"},
		{stdout, "--- PASS: TestBefore (0.00s)\n=== RUN   TestDuring\n"},
		{stderr, "oops"},
		{stdout, "--- PASS: TestDuring (0.00s)\n=== RUN   TestAfter\n"},
		{stderr, "ping"},
	} {
		if _, err := entry.stream.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	got := guardTests(capture, 1, []embargo.Finding{{Start: 4, End: 8}}, guardPolicy(nil))
	if got != "TestDuring" {
		t.Fatal(got)
	}
}

func TestGuardJoinedNamesCannotRecreateCanary(t *testing.T) {
	t.Parallel()
	const canary = "TestAlpha, TestBeta"
	data := []byte("=== RUN   TestAlpha\n=== RUN   TestBeta\n" + canary)
	capture := &guardCapture{data: [2][]byte{data, nil}}
	policy := guardPolicy([]Option{WithCanary([]byte(canary))})
	got := guardTests(capture, 0, []embargo.Finding{{Start: len(data) - len(canary), End: len(data)}}, policy)
	if got != "[redacted test name]" {
		t.Fatalf("joined diagnostic exposed canary: %q", got)
	}
}

type countingNameDetector struct{ calls int }

func (d *countingNameDetector) Kind() embargo.Kind { return "name_counter" }
func (d *countingNameDetector) Hints() []string    { return nil }
func (d *countingNameDetector) Scan(_ []byte) []embargo.Finding {
	d.calls++
	return nil
}

func TestGuardValidatesEachDistinctNameOnce(t *testing.T) {
	t.Parallel()
	detector := &countingNameDetector{}
	policy := guardPolicy([]Option{WithScanner(embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector)))})
	data := []byte("=== RUN   TestOnce\n" + strings.Repeat("x", 100))
	capture := &guardCapture{data: [2][]byte{data, nil}}
	findings := make([]embargo.Finding, 100)
	for i := range findings {
		findings[i] = embargo.Finding{Start: len(data) - 100 + i, End: len(data) - 99 + i}
	}
	got := guardTests(capture, 0, findings, policy)
	if got != "TestOnce" || detector.calls > 2 {
		t.Fatalf("got %q with %d detector calls; want one name check and one joined check", got, detector.calls)
	}
}
