package tests

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

const pipeFixtureOS = "linux"

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// failedCapture intercepts intentional Check failures while retaining testing's lifecycle.
type failedCapture struct {
	testing.TB

	failed bool
}

func (f *failedCapture) Error(...any) { f.failed = true }

func TestLifecycleChild(t *testing.T) {
	t.Parallel()
	//nolint:goconst // Match the literal top-level helper name in an isolated child.
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestLifecycleChild" {
		return
	}
	//nolint:forbidigo // Real child stdout exercises os/exec pipe ownership.
	if _, err := fmt.Println("completed"); err != nil {
		t.Fatal(err)
	}
}

func TestLifecyclePanic(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestLifecyclePanic" {
		return
	}
	panic(embargo.NewSecret("public-fake-canary-0123456789"))
}

func TestLifecycleWait(t *testing.T) {
	t.Parallel()
	//nolint:goconst // Match the literal top-level helper name in an isolated child.
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestLifecycleWait" {
		return
	}
	<-t.Context().Done()
}

func TestRunJoinsChildGoroutines(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, helper  string
		exit          int
		timeout       time.Duration
		cancel, fails bool
	}{
		{name: "success", helper: "TestLifecycleChild", timeout: 5 * time.Second},
		{name: "panic", helper: "TestLifecyclePanic", exit: 2, timeout: 5 * time.Second},
		//nolint:goconst // Independent acceptance scenarios keep their literal expected results local.
		{name: "missing", helper: "TestLifecycleAbsent", timeout: 5 * time.Second, fails: true},
		{name: "exit mismatch", helper: "TestLifecycleChild", exit: 1, timeout: 5 * time.Second, fails: true},
		{name: "cancel", helper: "TestLifecycleWait", timeout: 5 * time.Second, cancel: true, fails: true},
		{name: "deadline", helper: "TestLifecycleWait", timeout: 100 * time.Millisecond, fails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			probe := &failedCapture{TB: t}
			recorder := embargotest.New(probe, embargotest.WithMaxBytes(1<<20), embargotest.WithTimeout(tc.timeout))
			recorder.Expect("stdout", func(data []byte) bool { return len(data) > 0 })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			err := recorder.Run(ctx, tc.helper, tc.exit)
			if (err != nil) != tc.fails {
				t.Fatal("unexpected child lifecycle result")
			}
			if recorder.Check() == tc.fails {
				t.Fatal("unexpected observation result")
			}
		})
	}
}

type directoryTB struct {
	*failedCapture

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

// A field decoder cannot clear a value when encoding/json never calls it.
func TestInputOuterDecode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		text    string
		wantErr bool
	}{
		{name: "absent field retains earlier value", text: `{}`},
		{name: "invalid outer JSON retains earlier value", text: `{"token":"new"`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var reused, fresh struct {
				Token embargo.Input[string] `json:"token"`
			}
			if err := reused.Token.UnmarshalText([]byte("previous")); err != nil {
				t.Fatal(err)
			}

			if err := json.Unmarshal([]byte(tc.text), &reused); (err != nil) != tc.wantErr {
				t.Fatalf("reused object: unexpected error %v", err)
			}
			if got := reused.Token.Secret().Reveal(); got != "previous" {
				t.Fatalf("field decoder was unexpectedly called: %q", got)
			}

			if err := json.Unmarshal([]byte(tc.text), &fresh); (err != nil) != tc.wantErr {
				t.Fatalf("fresh object: unexpected error %v", err)
			}
			if got := fresh.Token.Secret().Reveal(); got != "" {
				t.Fatalf("fresh object retained a value: %q", got)
			}
		})
	}
}
