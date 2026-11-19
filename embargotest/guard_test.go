package embargotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nao1215/embargo"
)

//nolint:goconst // Keep child modes and their expected diagnostics together.
func TestPackageGuard(t *testing.T) {
	t.Parallel()
	const safeMode = "safe"
	binary := filepath.Join(t.TempDir(), "guard.test.exe")
	// #nosec G204 -- Fixed Go command and test package, output path from TempDir.
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", binary, "./testdata/guard")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	for _, mode := range []string{safeMode, "stdout", "stderr", "slog", "tlog", "detector", "subtest", "panic", "subprocess", "overflow", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			args := []string{}
			if mode == "stdout" {
				args = append(args, "-test.run=^TestPackageOutput$")
			}
			// #nosec G204 -- The binary is built above; arguments select a fixed fixture test.
			cmd := exec.CommandContext(t.Context(), binary, args...)
			cmd.Env = append(os.Environ(), "GUARD_CASE="+mode)
			output, err := cmd.CombinedOutput()
			if (err == nil) != (mode == safeMode) {
				t.Fatalf("wrong verdict: %v %s", err, output)
			}
			if incompleteGuardMode(mode) {
				if !bytes.Contains(output, []byte("incomplete, truncated or timed out")) {
					t.Fatal("missing incomplete capture diagnosis")
				}
				return
			}
			if mode != safeMode && (!bytes.Contains(output, []byte("active tests:")) || !bytes.Contains(output, []byte("embargotest: package leak"))) {
				t.Fatalf("missing diagnosis: %s", output)
			}
			if mode == "subtest" && !bytes.Contains(output, []byte("TestPackageOutput/leaking_child")) {
				t.Fatalf("missing leaking subtest name: %s", output)
			}
			if mode == "stdout" {
				checkGuardSnapshot(t, output)
			}
			if bytes.Contains(output, []byte(defaultCanary)) {
				t.Fatal("guard repeated the canary")
			}
		})
	}
	testGuardArguments(t, binary)
}

func testGuardArguments(t *testing.T, binary string) {
	t.Helper()
	for _, args := range [][]string{{"positional"}, {"-test.v=test2json"}} {
		t.Run(args[0], func(t *testing.T) {
			t.Parallel()
			// #nosec G204 -- Built test fixture, fixed case arguments, no shell.
			cmd := exec.CommandContext(t.Context(), binary, args...)
			cmd.Env = append(os.Environ(), "GUARD_CASE=safe")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child failed: %v %s", err, out)
			}
			if !bytes.Contains(out, []byte("=== RUN")) {
				t.Error("positional argument disabled verbose capture")
			}
			if args[0] == "-test.v=test2json" && !bytes.Contains(out, []byte{0x16}) {
				t.Error("test2json framing was lost")
			}
		})
	}
}

func checkGuardSnapshot(t *testing.T, output []byte) {
	t.Helper()
	for line := range bytes.SplitSeq(output, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("embargotest: package leak")) {
			continue
		}
		want, err := os.ReadFile("testdata/guard-failure.golden")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(append(bytes.Clone(line), '\n'), want) {
			t.Fatal("Guard diagnostic snapshot changed")
		}
		return
	}
	t.Fatal("Guard diagnostic missing")
}

func incompleteGuardMode(mode string) bool { return mode == "overflow" || mode == "timeout" }

func TestGuardForgedTestNamesNeverReachDiagnostics(t *testing.T) {
	t.Parallel()
	const attacker = "opaque-private-value-not-known-to-detectors"
	for _, prefix := range []string{"=== RUN   ", "\x16=== RUN   "} {
		data := []byte(prefix + attacker + "\n" + defaultCanary)
		got := guardTests(&guardCapture{data: [2][]byte{data, nil}}, 0, []embargo.Finding{{Start: len(prefix) + len(attacker) + 1, End: len(data)}}, guardPolicy([]Option{WithCanary([]byte(attacker))}))
		if strings.Contains(got, attacker) {
			t.Fatal("untrusted stream framing echoed input into a Guard diagnostic")
		}
	}
}

//nolint:goconst // Child modes match the independent supervisor cases below.
func TestGuardCaptureChild(t *testing.T) {
	t.Parallel()
	mode := os.Getenv("EMBARGO_CAPTURE_CHILD")
	switch mode {
	case "safe":
		if _, err := fmt.Fprintln(os.Stdout, "public output"); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(os.Stderr, "public diagnostic"); err != nil {
			t.Fatal(err)
		}
	case "leak":
		if _, err := fmt.Fprintln(os.Stdout, defaultCanary); err != nil {
			t.Fatal(err)
		}
	case "overflow":
		if _, err := fmt.Fprintln(os.Stdout, strings.Repeat("public output", 512)); err != nil {
			t.Fatal(err)
		}
	case "failure":
		t.Error("intentional child failure")
	case "wait":
		<-t.Context().Done()
	}
}

type rejectedReplay struct{}

func (rejectedReplay) Write([]byte) (int, error) { return 0, errors.New("sink closed") }

func TestGuardCaptureAndReplay(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"safe", "leak", "overflow", "failure", "wait", "start-failure", "write-failure", "scanner-failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			policy := guardPolicy(nil)
			policy.maxBytes = 1024
			ctx := t.Context()
			if mode == "wait" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			binary := executable
			if mode == "start-failure" {
				binary = executable + ".missing"
			}
			// #nosec G204 -- The executable is this test binary, or its deliberately nonexistent sibling.
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestGuardCaptureChild$", "-test.v")
			cmd.Env = append(os.Environ(), "EMBARGO_CAPTURE_CHILD="+mode)
			if mode == "scanner-failure" {
				policy.scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(&panickingGuardDetector{}))
			}
			var stdout, stderr bytes.Buffer
			var code int
			if mode == "write-failure" {
				code = guardCommand(ctx, cmd, policy, rejectedReplay{}, &stderr)
			} else {
				code = guardCommand(ctx, cmd, policy, &stdout, &stderr)
			}
			if (code == 0) != (mode == "safe") {
				t.Fatalf("unexpected exit %d", code)
			}
			if mode == "safe" && (!strings.Contains(stdout.String(), "public output") || !strings.Contains(stderr.String(), "public diagnostic")) {
				t.Fatal("safe output was lost")
			}
			if strings.Contains(stdout.String(), defaultCanary) {
				t.Fatal("leak was replayed")
			}
		})
	}
}

type panickingGuardDetector struct{}

func (*panickingGuardDetector) Scan([]byte) []embargo.Finding { panic("must not escape") }

func TestGuardNamesAndPolicy(t *testing.T) {
	t.Parallel()
	policy := guardPolicy([]Option{nil, WithMaxBytes(16), WithTimeout(time.Second)})
	if policy.invalid || policy.maxBytes != 16 || policy.timeout != time.Second {
		t.Fatal("guard options lost")
	}
	if !guardPolicy([]Option{WithMaxBytes(-1)}).invalid {
		t.Fatal("invalid guard option accepted")
	}
}

func TestGuardSharedOutputLimit(t *testing.T) {
	t.Parallel()
	capture := &guardCapture{maxBytes: 64}
	writers := [2]*guardStream{{capture: capture, index: 0}, {capture: capture, index: 1}}
	var wg sync.WaitGroup
	for _, writer := range writers {
		wg.Go(func() {
			for range 10 {
				n, err := writer.Write([]byte("abcdefgh"))
				if n != 8 || err != nil {
					t.Error("short capture write")
				}
			}
		})
	}
	wg.Wait()
	if !capture.overflow || capture.retained != 64 || len(capture.data[0])+len(capture.data[1]) != 64 {
		t.Fatal("shared byte limit was lost")
	}
}

func modelTraces[T any](t *testing.T, name string) [][]T {
	t.Helper()
	// #nosec G304 -- Only the two fixed local model names are passed by these tests.
	data, err := os.ReadFile("../tests/models/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Traces [][]T `json:"traces"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Traces) != 64 {
		t.Fatal("missing model traces")
	}
	return fixture.Traces
}

type recorderState struct {
	Op       string `json:"op"`
	Writers  []int  `json:"writers"`
	Expected []int  `json:"expected"`
	Size     int    `json:"size"`
	Checked  bool   `json:"checked"`
	Failed   bool   `json:"failed"`
	Reported bool   `json:"reported"`
	Errors   int    `json:"errors"`
	Which    int    `json:"which"`
}

func TestGuardModelChild(t *testing.T) {
	t.Parallel()
	raw := os.Getenv("EMBARGO_MODEL_CHILD")
	if raw == "" {
		return
	}
	var trace []guardState
	if err := json.Unmarshal([]byte(raw), &trace); err != nil {
		os.Exit(9)
	}
	for _, state := range trace {
		chunk := []byte("public-model-output-padding-0000")
		if state.Op == "leak" {
			chunk = []byte(defaultCanary)
		}
		if state.Op == "safe" || state.Op == "leak" {
			var out io.Writer = os.Stdout
			if state.Which == 1 {
				out = os.Stderr
			}
			if _, err := out.Write(chunk); err != nil {
				os.Exit(8)
			}
		}
		if state.Op == "timeout" {
			// Far beyond the parent's 100 ms deadline, but bounded, so a child
			// whose parent was killed (for example by a mutation timeout) exits.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			<-ctx.Done()
			cancel()
			os.Exit(7)
		}
		if state.Op == "exitFailure" {
			os.Exit(2)
		}
	}
	os.Exit(0)
}

//nolint:gocognit,paralleltest,tparallel // Replay each trace sequentially; child timing and process-wide pipes are part of the model.
func TestQuintGuardReplay(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for i, trace := range modelTraces[guardState](t, "guard") {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			capture := &guardCapture{maxBytes: 128}
			var last guardState
			for _, state := range trace {
				if state.Op == "safe" || state.Op == "leak" {
					writer := &guardStream{capture: capture, index: state.Which}
					if _, err := writer.Write(bytes.Repeat([]byte("x"), 32)); err != nil {
						t.Fatal(err)
					}
				}
				if capture.retained != int64((state.Sizes[0]+state.Sizes[1])*32) || capture.overflow != state.Overflow {
					t.Fatal("capture differs from model")
				}
				last = state
			}
			if last.Phase != 2 {
				return
			} // Finite trace ended before the child exited.
			raw, err := json.Marshal(trace)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if last.Timeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestGuardModelChild$")
			cmd.Env = append(os.Environ(), "EMBARGO_MODEL_CHILD="+string(raw))
			policy := guardPolicy([]Option{WithMaxBytes(128), WithTimeout(time.Second)})
			if last.ScannerFailed {
				policy.scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(&panickingGuardDetector{}))
			}
			var stdout, stderr bytes.Buffer
			code := guardCommand(ctx, cmd, policy, &stdout, &stderr)
			if code != last.Code {
				t.Fatalf("exit %d != %d", code, last.Code)
			}
			for stream, output := range [][]byte{stdout.Bytes(), stderr.Bytes()} {
				want := 0
				if slices.Contains(last.Replay, stream) {
					want = last.Sizes[stream] * 32
				}
				if len(output) != want || bytes.Contains(output, []byte(defaultCanary)) {
					t.Fatalf("stream %d: replay differs from model", stream)
				}
			}
		})
	}
}

func TestGuardParentAndInvalidAPI(t *testing.T) {
	t.Parallel()
	if Guard(nil) != 1 {
		t.Fatal("nil test runner accepted")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"safe", "leak"} {
		var out, diagnostic bytes.Buffer
		code := guardParent(executable, []string{"-test.run=^TestGuardParentChild$", "-test.v", "--", mode}, guardPolicy(nil), &out, &diagnostic)
		if (code == 0) != (mode == "safe") || strings.Contains(out.String(), defaultCanary) || strings.Contains(diagnostic.String(), defaultCanary) {
			t.Fatalf("supervisor verdict=%d out=%s diagnostic=%s", code, out.String(), diagnostic.String())
		}
		if mode == "safe" && !strings.Contains(out.String(), "public supervisor output") {
			t.Fatal("safe child output was lost")
		}
	}
}

func TestGuardParentChild(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_PACKAGE_GUARD") != "child" {
		return
	}
	message := "public supervisor output"
	if os.Args[len(os.Args)-1] == "leak" {
		message = defaultCanary
	}
	if _, err := fmt.Fprintln(os.Stdout, message); err != nil {
		t.Fatal(err)
	}
}

func TestGuardWithoutExecutable(t *testing.T) {
	t.Parallel()
	unavailable := func() (string, error) { return "", errors.New("no executable") }
	if code := guardSupervise(&testing.M{}, unavailable, nil); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
}
