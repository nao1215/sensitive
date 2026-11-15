package embargotest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nao1215/embargo"
)

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
	policy := guardPolicy([]Option{nil, WithLimits(16, time.Second)})
	if policy.failed || policy.maxBytes != 16 || policy.timeout != time.Second {
		t.Fatal("guard options lost")
	}
	if !guardPolicy([]Option{WithLimits(-1, time.Second)}).failed {
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
