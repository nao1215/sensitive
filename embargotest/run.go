package embargotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Run executes a named top-level Test helper in the current test executable and
// appends its output to the stdout and stderr sinks. Unexpected exits, timeouts
// and incomplete output fail Check; returned errors never contain child output.
// See the package Child processes section for the required helper guard and
// environment protocol.
func (r *Recorder) Run(ctx context.Context, helper string, wantExit int) error {
	executable, err := os.Executable()
	if err != nil {
		return r.runFailure("embargotest: executable unavailable")
	}
	return r.run(ctx, executable, helper, wantExit)
}

func (r *Recorder) run(ctx context.Context, executable, helper string, wantExit int) error {
	if ctx == nil || !validHelper(helper) || wantExit < 0 || wantExit > 255 || os.Getenv("EMBARGO_TEST_CHILD") != "" {
		return r.runFailure("embargotest: invalid child request")
	}
	r.mu.Lock()
	if r.checked || r.running != 0 {
		r.failed = true
		r.mu.Unlock()
		return errors.New("embargotest: child execution unavailable")
	}
	r.running++
	stdout, stderr := r.writer("stdout"), r.writer("stderr")
	start := len(stdout.data)
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.running--; r.mu.Unlock() }()
	bounded, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	// The executable comes from os.Executable; the helper is an escaped test name.
	cmd := exec.CommandContext(bounded, executable, "-test.run=^"+regexp.QuoteMeta(helper)+"$", "-test.v", "-test.count=1") // #nosec G204 -- current test executable, never a shell command.
	cmd.Env = []string{"EMBARGO_TEST_CHILD=" + helper, "EMBARGO_TEST_CANARY=" + base64.StdEncoding.EncodeToString(r.canary)}
	if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
		cmd.Env = append(cmd.Env, "SystemRoot="+systemRoot)
	}
	cmd.Dir = r.tb.TempDir()
	cmd.Env = append(cmd.Env, "TMPDIR="+cmd.Dir, "TMP="+cmd.Dir, "TEMP="+cmd.Dir)
	stdoutCopy, stderrCopy := &childOutput{stream: stdout}, &childOutput{stream: stderr}
	cmd.Stdout, cmd.Stderr = stdoutCopy, stderrCopy
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = childWaitDelay
	if err := cmd.Start(); err != nil {
		if bounded.Err() != nil {
			r.markFailed()
			return bounded.Err()
		}
		return r.runFailure("embargotest: child start failed")
	}
	waitErr := cmd.Wait()
	if bounded.Err() != nil {
		r.markFailed()
		return bounded.Err()
	}
	// Wait reports an ExitError in preference to ErrWaitDelay, so a pipe
	// that WaitDelay cut off is detected from the copies themselves.
	var exitErr *exec.ExitError
	if (waitErr != nil && !errors.As(waitErr, &exitErr)) || !stdoutCopy.complete || !stderrCopy.complete {
		return r.runFailure("embargotest: child output incomplete")
	}
	r.mu.Lock()
	started := bytes.Contains(stdout.data[start:], []byte("=== RUN   "+helper+"\n"))
	r.mu.Unlock()
	if !started || cmd.ProcessState.ExitCode() != wantExit {
		return r.runFailure("embargotest: child execution mismatch")
	}
	return nil
}

// childOutput records whether os/exec copied a child pipe up to EOF. os/exec
// copies with io.Copy, which uses ReadFrom; complete stays false when the copy
// ends with an error, such as WaitDelay closing a pipe that is still held open.
// Wait joins the copying goroutine before complete is read.
type childOutput struct {
	stream   *stream
	complete bool
}

// Write captures child output under the shared limit.
func (c *childOutput) Write(p []byte) (int, error) { return c.stream.Write(p) }

// ReadFrom drains the child reader through the same bounded capture path.
func (c *childOutput) ReadFrom(src io.Reader) (int64, error) {
	var total int64
	//nolint:mnd // This bound follows HTTP sniffing, JSON nesting, metadata encoding, or child-name limits.
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, _ := c.Write(buf[:n]) //nolint:errcheck // childOutput.Write only calls stream.Write, which always consumes the full input without an error.
			total += int64(written)
		}
		if errors.Is(err, io.EOF) {
			c.complete = true
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func validHelper(name string) bool {
	if !strings.HasPrefix(name, "Test") || len(name) <= 4 || len(name) > maxNameBytes {
		return false
	}
	for _, ch := range name {
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}
	return true
}
func (r *Recorder) markFailed()                     { r.mu.Lock(); r.failed = true; r.mu.Unlock() }
func (r *Recorder) runFailure(message string) error { r.markFailed(); return errors.New(message) }
