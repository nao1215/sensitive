//go:build linux

package tests

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nao1215/embargo/embargotest"
)

type directoryTB struct {
	*failedCapture

	directory string
}

func (t *directoryTB) TempDir() string { return t.directory }

// TestPipeTransfer transfers a duplicate stdout pipe to the supervising test.
// It models an inherited pipe without launching an unmanaged descendant.
func TestPipeTransfer(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestPipeTransfer" {
		return
	}
	transferStdout(t)
}

// transferStdout sends a duplicate of this process's stdout to the supervising
// test over pipe.sock in the working directory.
func transferStdout(t *testing.T) {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "pipe.sock", Net: "unix"})
	if err != nil {
		t.Fatal("fixture connection failed")
	}
	if _, _, err := connection.WriteMsgUnix([]byte{1}, syscall.UnixRights(int(os.Stdout.Fd())), nil); err != nil {
		t.Error("fixture descriptor transfer failed")
	}
	if err := connection.Close(); err != nil {
		t.Error("fixture connection close failed")
	}
}

// TestPipeTransferExit is TestPipeTransfer followed by a nonzero exit, as a
// panicking helper would end.
func TestPipeTransferExit(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestPipeTransferExit" {
		return
	}
	transferStdout(t)
	os.Exit(7)
}

func TestRunWaitDelay(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		helper string
		exit   int
	}{{helper: "TestPipeTransfer", exit: 0}, {helper: "TestPipeTransferExit", exit: 7}} {
		t.Run(tc.helper, func(t *testing.T) { t.Parallel(); runWaitDelay(t, tc.helper, tc.exit) })
	}
}

// runWaitDelay holds a duplicate of the child's stdout while the child exits
// with exit. Run must report incomplete output whatever the exit code.
func runWaitDelay(t *testing.T, helper string, exit int) {
	t.Helper()
	directory := t.TempDir()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "pipe.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	if deadlineErr := listener.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
		t.Fatal(deadlineErr)
	}
	probe := &directoryTB{failedCapture: &failedCapture{TB: t}, directory: directory}
	r := embargotest.New(probe)
	r.Expect("stdout", func([]byte) bool { return true })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan struct{})
	var runErr error
	go func() { defer close(done); runErr = r.Run(ctx, helper, exit) }()
	defer func() { cancel(); <-done }()
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal("fixture accept failed")
	}
	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	if deadlineErr := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
		t.Fatal(deadlineErr)
	}
	data, control := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	//nolint:dogsled // Only the ancillary descriptor bytes are relevant to this pipe-lifetime fixture.
	_, n, _, _, err := connection.ReadMsgUnix(data, control)
	if err != nil {
		t.Fatal("fixture receive failed")
	}
	messages, err := syscall.ParseSocketControlMessage(control[:n])
	if err != nil || len(messages) != 1 {
		t.Fatal("fixture control message invalid")
	}
	descriptors, err := syscall.ParseUnixRights(&messages[0])
	if err != nil || len(descriptors) != 1 || descriptors[0] < 0 {
		t.Fatal("fixture descriptor invalid")
	}
	held := os.NewFile(uintptr(descriptors[0]), "held-child-output")
	defer func() {
		if err := held.Close(); err != nil {
			t.Error(err)
		}
	}()
	// Hold the duplicate until Run returns: WaitDelay must close and join readers.
	<-done
	if runErr == nil || runErr.Error() != "embargotest: child output incomplete" {
		t.Fatal("pipe delay not reported")
	}
	if r.Check() {
		t.Fatal("incomplete pipe passed")
	}
}
