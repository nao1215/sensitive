package embargotest

import (
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
