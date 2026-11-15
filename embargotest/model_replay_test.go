package embargotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/nao1215/embargo"
)

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

func TestQuintRecorderReplay(t *testing.T) {
	t.Parallel()
	for _, trace := range modelTraces[recorderState](t, "recorder") {
		probe := &probeTB{TB: t}
		recorder := New(probe, WithLimits(4, time.Second), WithScanner(embargo.NewScanner(embargo.WithKinds())))
		for _, state := range trace {
			switch state.Op {
			case "init":
			case "write":
				if _, err := io.WriteString(recorder.Writer(strconv.Itoa(state.Which)), "x"); err != nil {
					t.Fatal(err)
				}
			case "expect":
				recorder.Expect(strconv.Itoa(state.Which), func([]byte) bool { return true })
			case "check":
				if recorder.Check() == state.Failed {
					t.Fatal("Check disagrees with model")
				}
			case "cleanup":
				probe.finish()
			default:
				t.Fatal("unknown model operation")
			}
			if recorder.retained != int64(state.Size) || recorder.checked != state.Checked || recorder.failed != state.Failed || recorder.reported != state.Reported || (probe.errors > 0) != (state.Errors > 0) {
				t.Fatalf("state mismatch after %s: model=%+v", state.Op, state)
			}
			for _, w := range []int{0, 1} {
				_, got := recorder.sinks[strconv.Itoa(w)]
				if got != slices.Contains(state.Writers, w) {
					t.Fatal("writer registration changed")
				}
			}
		}
	}
}

//nolint:tagliatelle // Quint trace field names are the external schema.
type guardState struct {
	Op            string `json:"op"`
	Sizes         []int  `json:"sizes"`
	Leaks         []int  `json:"leaks"`
	Replay        []int  `json:"replay"`
	Phase         int    `json:"phase"`
	Overflow      bool   `json:"overflow"`
	Timeout       bool   `json:"timeout"`
	ScannerFailed bool   `json:"scannerFailed"`
	ExitFailed    bool   `json:"exitFailed"`
	Code          int    `json:"code"`
	Which         int    `json:"which"`
}

// Child mode uses real OS pipes but exits before the testing runner prints its
// own framing, so one modeled chunk corresponds to exactly 32 captured bytes.
//
//nolint:goconst // Literal event names are the independent model protocol.
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
			select {}
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
			policy := guardPolicy([]Option{WithLimits(128, time.Second)})
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
