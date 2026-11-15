package embargotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

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
