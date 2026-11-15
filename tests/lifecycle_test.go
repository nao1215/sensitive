package tests

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

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
			recorder := embargotest.New(probe, embargotest.WithLimits(1<<20, tc.timeout))
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
