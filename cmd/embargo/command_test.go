package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// childArgument makes the test binary act as the command that run starts,
// so the tests need no shell and work on Windows too.
const childArgument = "embargo-test-child"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == childArgument {
		os.Exit(child(os.Args[2]))
	}
	os.Exit(m.Run())
}

// child writes a secret to each stream, or copies stdin, and returns a status.
func child(mode string) int {
	switch mode {
	case "leak":
		_, _ = os.Stdout.WriteString("out " + filterEmail + "\n") //nolint:errcheck // The test reads what arrived.
		_, _ = os.Stderr.WriteString("err " + filterPAN + "\n")   //nolint:errcheck // The test reads what arrived.
		return 3
	case "echo":
		_, _ = io.Copy(os.Stdout, os.Stdin) //nolint:errcheck // The test reads what arrived.
		return 0
	case "long":
		_, _ = os.Stdout.WriteString(strings.Repeat("x", maximumLine+1) + "\n") //nolint:errcheck // The test reads what arrived.
		return 0
	case "term":
		process, _ := os.FindProcess(os.Getpid()) //nolint:errcheck // The own process is always found.
		_ = process.Signal(syscall.SIGTERM)       //nolint:errcheck // The test checks the status.
		select {}
	default:
		return 0
	}
}

func runChild(t *testing.T, stdin, mode string) (code int, stdout, stderr string) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	code = exitCode([]string{runOperand, os.Args[0], childArgument, mode}, strings.NewReader(stdin), &out, &diagnostics)
	return code, out.String(), diagnostics.String()
}

func TestRunMasksBothStreamsAndKeepsTheStatus(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runChild(t, "", "leak")
	if code != 3 || stdout != "out "+filterMarker+"\n" || stderr != "err "+filterMarker+"\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, _ = runChild(t, "in "+filterEmail+"\n", "echo")
	if code != 0 || stdout != "in "+filterMarker+"\n" {
		t.Fatalf("stdin: code=%d stdout=%q", code, stdout)
	}
	var out bytes.Buffer
	if code := exitCode([]string{flagKinds, "pan", runOperand, "--", os.Args[0], childArgument, "leak"}, strings.NewReader(""), &out, io.Discard); code != 3 || out.String() != "out "+filterEmail+"\n" {
		t.Fatalf("flags before run: code=%d stdout=%q", code, out.String())
	}
}

func TestRunReportsAMaskingFailureAfterASuccessfulCommand(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runChild(t, "", "long")
	if code != statusFailed || stdout != "" || stderr != "embargo: line 1 exceeds the 4 MiB limit; output stops before it\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRunReportsASignalAsAShellDoes(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no signals")
	}
	if code, _, _ := runChild(t, "", "term"); code != signalBase+int(syscall.SIGTERM) {
		t.Fatalf("code=%d", code)
	}
}

func TestRunCommandThatCannotStart(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		want string
		args []string
		code int
	}{
		{args: []string{runOperand, "embargo-no-such-command"}, code: statusNotFound, want: "embargo: the command was not found\n"},
		{args: []string{runOperand}, code: statusUsage, want: "embargo: run needs a command; see embargo --help\n"},
		{args: []string{runOperand, "--"}, code: statusUsage, want: "embargo: run needs a command; see embargo --help\n"},
		{args: []string{flagFormat, formatJSON, runOperand, "x"}, code: statusUsage, want: "embargo: run writes text only; --format cannot be used with it\n"},
	} {
		var out, diagnostics bytes.Buffer
		if code := exitCode(tc.args, strings.NewReader(""), &out, &diagnostics); code != tc.code || out.Len() != 0 || diagnostics.String() != tc.want {
			t.Errorf("%v: code=%d stderr=%q", tc.args, code, diagnostics.String())
		}
	}
	parsed, err := parseOptions([]string{"--", runOperand})
	if err != nil || parsed.command != nil || strings.Join(parsed.files, ",") != runOperand {
		t.Fatalf("-- run must read a file named run: %+v, %v", parsed, err)
	}
}

func TestStartFailureAndStatusMapping(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err  error
		want string
		code int
	}{
		{err: os.ErrPermission, code: statusCannotRun, want: "embargo: the command cannot be run: permission denied"},
		{err: errors.New("private-error"), code: statusCannotRun, want: "embargo: the command cannot be run"},
	} {
		status, ok := errors.AsType[statusError](startFailure(tc.err))
		if !ok || status.code != tc.code || status.Error() != tc.want {
			t.Errorf("%v: %+v", tc.err, status)
		}
	}
	if (statusError{cause: nil, code: 4}).Error() != "embargo: the command failed" {
		t.Error("an exit status without a cause has no text")
	}
	if status, ok := errors.AsType[statusError](commandStatus(errors.New("wait failed"), nil)); !ok || status.code != statusFailed {
		t.Errorf("a failed wait: %+v", status)
	}
	if !errors.Is(commandStatus(nil, []error{nil, errOutputClosed}), errOutputClosed) {
		t.Error("a closed output is not reported quietly")
	}
	if commandStatus(nil, []error{nil, nil}) != nil {
		t.Error("a successful command failed")
	}
}

func TestClosedOutputEndsQuietly(t *testing.T) {
	t.Parallel()
	var diagnostics bytes.Buffer
	if code := exitCode(nil, strings.NewReader("line\n"), closedOutput{}, &diagnostics); code != statusClosedOutput || diagnostics.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, diagnostics.String())
	}
	if !outputClosed(syscall.EPIPE) || outputClosed(errors.New("other")) {
		t.Fatal("outputClosed misreads EPIPE")
	}
	if err := writeFailed(errors.New("private-error")); err.Error() != outputWriteFailed {
		t.Fatalf("writeFailed = %v", err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], childArgument, "none") // #nosec G204 G702 -- The test binary runs itself.
	pipes, err := commandStreams(cmd)
	if err != nil || cmd.Stdout == nil || cmd.Stderr == nil {
		t.Fatalf("commandStreams: %v", err)
	}
	pipes.close()
}

// closedOutput fails every write as a pipe whose reader has gone.
type closedOutput struct{}

func (closedOutput) Write([]byte) (int, error) { return 0, syscall.EPIPE }
