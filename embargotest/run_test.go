package embargotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const pipeFixtureOS = "linux"

func TestChildSafe(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestChildSafe" {
		return
	}
	if os.Getenv("EMBARGO_PARENT_SECRET") != "" {
		panic("inherited parent environment")
	}
	//nolint:forbidigo // The example or isolated child deliberately writes to captured stdout.
	//nolint:forbidigo // Isolated child output is the behavior under test.
	if _, err := fmt.Println("public result"); err != nil {
		t.Fatal(err)
	}
}

func TestChildHang(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestChildHang" {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	<-ctx.Done()
}

func TestChildPanic(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestChildPanic" {
		return
	}
	panic("public failure")
}

func TestChildLeak(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestChildLeak" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("EMBARGO_TEST_CANARY"))
	if err != nil {
		t.Fatal("canary decode failed")
	}
	//nolint:forbidigo // The example or isolated child deliberately writes to captured stdout.
	if _, err := fmt.Print(string(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestChildFlood(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestChildFlood" {
		return
	}
	//nolint:forbidigo // The example or isolated child deliberately writes to captured stdout.
	if _, err := fmt.Print(strings.Repeat("x", 2<<20)); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	t.Setenv("EMBARGO_PARENT_SECRET", "must-not-be-inherited")
	r := New(t)
	r.Expect("stdout", func(b []byte) bool { return bytes.Contains(b, []byte("public result")) })
	r.Expect("stderr", func(b []byte) bool { return len(b) == 0 })
	if err := r.Run(context.Background(), "TestChildSafe", 0); err != nil {
		t.Fatal(err)
	}
	r.Check()
	p := New(t)
	p.Expect("stderr", func(b []byte) bool { return bytes.Contains(b, []byte("public failure")) })
	if err := p.Run(context.Background(), "TestChildPanic", 2); err != nil {
		t.Fatal(err)
	}
	p.Check()
}

func TestRunFailures(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"cancel-before", "timeout", "missing", "exit", "leak", "flood", "invalid-helper"} { //nolint:goconst // Child scenario names are repeated in independent tests.
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			p := &probeTB{TB: t}
			r := New(p, WithLimits(1024, 100*time.Millisecond))
			ctx := context.Background()
			helper := "TestChildSafe"
			want := 0
			switch mode {
			case "cancel-before":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "timeout":
				helper = "TestChildHang"
			case "missing":
				helper = "TestChildAbsent"
			case "exit":
				want = 3
			case "leak":
				helper = "TestChildLeak"
			case "flood":
				helper = "TestChildFlood"
			case "invalid-helper":
				helper = "["
			}
			r.Expect("stdout", func([]byte) bool { return true })
			err := r.Run(ctx, helper, want)
			if mode != "leak" && mode != "flood" && err == nil {
				t.Fatal("incomplete run returned nil")
			}
			if r.Check() {
				t.Fatal("incomplete run passed")
			}
			p.finish()
		})
	}
}

func TestRunStartAndLifecycleFailures(t *testing.T) {
	for _, mode := range []string{"start", "nil-context", "bad-exit", "recursive", "checked", "running"} { //nolint:goconst // Child scenario names are repeated in independent tests.
		t.Run(mode, func(t *testing.T) {
			p := &probeTB{TB: t}
			r := New(p)
			r.Expect("stdout", func([]byte) bool { return true })
			var err error
			switch mode {
			case "start":
				err = r.run(context.Background(), "/nonexistent/embargo-test", "TestChildSafe", 0)
			case "nil-context":
				err = r.Run(nil, "TestChildSafe", 0) //nolint:staticcheck // Exercise rejection of an invalid caller context.
			case "bad-exit":
				err = r.Run(context.Background(), "TestChildSafe", 256)
			case "recursive":
				t.Setenv("EMBARGO_TEST_CHILD", "parent")
				err = r.Run(context.Background(), "TestChildSafe", 0)
			case "checked":
				r.checked = true
				err = r.Run(context.Background(), "TestChildSafe", 0)
			case "running":
				r.running = 1
				err = r.Run(context.Background(), "TestChildSafe", 0)
				r.running = 0
			}
			if err == nil || r.Check() {
				t.Fatal("run failure not detected")
			}
			p.finish()
		})
	}
}

func TestHelperNameBoundary(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"TestA", "Testa", "Testz", "TestZ", "Test0", "Test9", "Test_", "Test" + strings.Repeat("a", 124)} {
		if !validHelper(name) {
			t.Fatal("valid helper name rejected")
		}
	}
	for _, name := range []string{"Test", "", "Helper", "Test" + strings.Repeat("a", 125), "Test/", "Test:", "Test[", "Test`", "Test{", "Test@"} {
		if validHelper(name) {
			t.Fatal("invalid helper accepted")
		}
	}
}

func TestChildExit255(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestChildExit255" {
		return
	}
	//nolint:forbidigo // Isolated child output is the behavior under test.
	if _, err := fmt.Println("public exit result"); err != nil {
		t.Fatal(err)
	}
	os.Exit(255)
}

func TestRunExit255(t *testing.T) {
	t.Parallel()
	r := New(t)
	r.Expect("stdout", func(b []byte) bool { return bytes.Contains(b, []byte("public exit result")) })
	if err := r.Run(context.Background(), "TestChildExit255", 255); err != nil {
		t.Fatal("valid exit rejected")
	}
	r.Check()
}

type directoryTB struct {
	*probeTB

	directory string
}

func (t *directoryTB) TempDir() string { return t.directory }

// TestPipeTransfer transfers a duplicate stdout pipe to the supervising test.
// It models an inherited pipe without launching an unmanaged descendant.
func TestPipeTransfer(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != pipeFixtureOS {
		t.Skip("Linux descriptor-transfer fixture")
	}
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
	if _, _, err := connection.WriteMsgUnix([]byte{1}, descriptorMessage(t, os.Stdout.Fd()), nil); err != nil {
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
	if runtime.GOOS != pipeFixtureOS {
		t.Skip("Linux descriptor-transfer fixture")
	}
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestPipeTransferExit" {
		return
	}
	transferStdout(t)
	os.Exit(7)
}

func TestRunWaitDelay(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != pipeFixtureOS {
		t.Skip("Linux descriptor-transfer fixture")
	}
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
	probe := &directoryTB{probeTB: &probeTB{TB: t}, directory: directory}
	r := New(probe)
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
	data, control := make([]byte, 1), make([]byte, len(descriptorMessage(t, 0)))
	//nolint:dogsled // Only the ancillary descriptor bytes are relevant to this pipe-lifetime fixture.
	_, n, _, _, err := connection.ReadMsgUnix(data, control)
	if err != nil {
		t.Fatal("fixture receive failed")
	}
	descriptor := receivedDescriptor(t, control[:n])
	held := os.NewFile(descriptor, "held-child-output")
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
	probe.finish()
}

// Linux ancillary headers use a native-size length followed by level and type.
// Encoding the fixture here keeps the source portable; only Linux executes it.
func descriptorMessage(t *testing.T, descriptor uintptr) []byte {
	t.Helper()
	const word = strconv.IntSize / 8
	const header = word + 8
	const length = header + 4
	const padded = (length + word - 1) / word * word
	if descriptor > 1<<31-1 {
		t.Fatal("descriptor does not fit the kernel ABI")
	}
	data := make([]byte, padded)
	if word == 8 {
		binary.NativeEndian.PutUint64(data, length)
	} else {
		binary.NativeEndian.PutUint32(data, length)
	}
	binary.NativeEndian.PutUint32(data[word:], 1)
	binary.NativeEndian.PutUint32(data[word+4:], 1)
	binary.NativeEndian.PutUint32(data[header:], uint32(descriptor&(1<<31-1)))
	return data
}

func receivedDescriptor(t *testing.T, data []byte) uintptr {
	t.Helper()
	const word = strconv.IntSize / 8
	const header = word + 8
	expected := descriptorMessage(t, 0)
	if len(data) < header+4 || !bytes.Equal(data[:header], expected[:header]) {
		t.Fatal("fixture control message invalid")
	}
	return uintptr(binary.NativeEndian.Uint32(data[header:]))
}
