package embargotest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nao1215/embargo"
)

// Guard runs a package under an output supervisor. Use
// os.Exit(embargotest.Guard(m)) as the body of TestMain. The child keeps the
// process environment, default slog logger and stdout/stderr descriptors; the
// parent captures their real output, including t.Log, panics and inherited child
// descriptors. No process-global writers or loggers are replaced.
//
// Options use the Recorder policy, but Guard needs no expectations. The default
// timeout is 5 minutes and total retained output is 1 MiB. Overflow, timeout,
// scanner failure or any leak fails the package. Safe output is replayed only
// after checking. Reports name the stream and count test-start frames in that process;
// frames are untrusted and cannot attribute raw output to a test reliably.
// Independently redirected subprocess output and output before TestMain are
// outside this boundary. Fixtures must use the configured public fake canary.
// Explicit -test.v=false suppresses passing t.Log output; test2json framing is
// preserved. The default scanner omits unlabelled entropy tokens; supply a scanner
// with WithAll to include them. Allowances can exempt intentional public values.
// The internal supervisor environment variable is reserved and must not be set.
func Guard(m *testing.M, opts ...Option) int {
	const childEnv = "EMBARGO_PACKAGE_GUARD"
	if os.Getenv(childEnv) == "child" {
		return m.Run()
	}
	policy := guardPolicy(opts)
	if m == nil || policy.failed {
		guardMessage("embargotest: invalid package guard options")
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		guardMessage("embargotest: guard executable unavailable")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), policy.timeout)
	defer cancel()
	args := append([]string{"-test.v=true"}, os.Args[1:]...)
	// #nosec G204 G702 -- Re-exec this test binary with its own arguments, never a shell.
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = append(os.Environ(), childEnv+"=child")
	return guardCommand(ctx, cmd, policy, os.Stdout, os.Stderr)
}

// guardCommand owns capture and replay; tests exercise it with real child pipes
// while keeping the test runner's process globals unchanged.
func guardCommand(ctx context.Context, cmd *exec.Cmd, policy *Recorder, stdout, stderr io.Writer) int {
	capture := &guardCapture{maxBytes: policy.maxBytes}
	cmd.Stdout = &guardStream{capture: capture, index: 0}
	cmd.Stderr = &guardStream{capture: capture, index: 1}
	cmd.WaitDelay = childWaitDelay
	runErr := cmd.Run()
	var exitError *exec.ExitError
	if ctx.Err() != nil || (runErr != nil && !errors.As(runErr, &exitError)) || capture.overflow {
		guardMessage("embargotest: package output incomplete, truncated or timed out")
		return 1
	}
	code := 0
	if runErr != nil {
		code = 1
	}
	tests := guardTests(capture.data[0])
	for i, stream := range []string{"stdout", "stderr"} {
		data := capture.data[i]
		found, failed := policy.scan(data)
		if failed || found || containsCanary(data, policy.needles) {
			guardMessage("embargotest: package leak or scanner failure on " + stream + "; observed test-start frames: " + tests)
			code = 1
			continue
		}
		writer := stdout
		if i == 1 {
			writer = stderr
		}
		if _, err := writer.Write(data); err != nil {
			code = 1
		}
	}
	return code
}

func guardPolicy(opts []Option) *Recorder {
	const defaultGuardTimeout = 5 * time.Minute
	// No testing lifecycle or mutable capture is exposed by this policy object.
	//nolint:exhaustruct_v5 // Guard uses only policy fields; no Recorder capture lifecycle is registered.
	r := &Recorder{scanner: embargo.NewScanner(), canary: []byte(defaultCanary), maxBytes: defaultMaxBytes, timeout: defaultGuardTimeout, allowedKinds: map[embargo.Kind]bool{}, allowedValues: map[string]bool{}}
	for _, option := range opts {
		if option != nil && !option.apply(r) {
			r.failed = true
		}
	}
	r.needles = representations(r.canary)
	return r
}

type guardCapture struct {
	data               [2][]byte
	mu                 sync.Mutex
	retained, maxBytes int64
	overflow           bool
}
type guardStream struct {
	capture *guardCapture
	index   int
}

// Write drains the child while retaining at most the shared capture limit.
func (w *guardStream) Write(data []byte) (int, error) {
	c := w.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := min(int64(len(data)), c.maxBytes-c.retained)
	c.data[w.index] = append(c.data[w.index], data[:keep]...)
	c.retained += keep
	c.overflow = c.overflow || keep < int64(len(data))
	return len(data), nil
}

// Child output is untrusted, including testing's text framing. Count frames,
// but never echo names: an opaque secret need not match any detector.
func guardTests(data []byte) string {
	count := 0
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		line = bytes.TrimPrefix(line, []byte{0x16})
		if bytes.HasPrefix(line, []byte("=== RUN   ")) {
			count++
		}
	}
	return strconv.Itoa(count)
}

func guardMessage(message string) {
	if _, err := os.Stderr.WriteString(message + "\n"); err != nil {
		return
	}
}
