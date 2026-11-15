//nolint:goconst // Runnable examples are self-contained and show the literal marker.
package embargotest_test

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

func ExampleCheckValue() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		return embargotest.CheckValue(tb, func(canary string) any { return embargo.NewSecret(canary) })
	})) // Output: true
}

func ExampleRecorder_Setenv() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb)
		r.Setenv("EMBARGO_EXAMPLE_PASSWORD")
		r.Expect("out", func(data []byte) bool { return string(data) == "[REDACTED]" })
		fmt.Fprint(r.Writer("out"), embargo.NewSecret(os.Getenv("EMBARGO_EXAMPLE_PASSWORD")))
		return r.Check()
	})) // Output: true
}

func ExampleRecorder_File() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb)
		path := r.File("password")
		// #nosec G304 -- Path was returned by the canary file helper in the private test directory.
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		r.Expect("out", func(data []byte) bool { return string(data) == "[REDACTED]" })
		fmt.Fprint(r.Writer("out"), embargo.NewSecret(data))
		return r.Check()
	})) // Output: true
}

func ExampleRecorder_Header() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb)
		header := r.Header("Authorization")
		r.Expect("out", func(data []byte) bool { return string(data) == "[REDACTED]" })
		fmt.Fprint(r.Writer("out"), embargo.NewSecret(header.Get("Authorization")))
		return r.Check()
	})) // Output: true
}

func ExampleRecorder_Reader() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb)
		data, err := io.ReadAll(r.Reader())
		if err != nil {
			return false
		}
		r.Expect("out", func(data []byte) bool { return string(data) == "[REDACTED]" })
		fmt.Fprint(r.Writer("out"), embargo.NewSecret(data))
		return r.Check()
	})) // Output: true
}

func ExampleGuard() {
	// testdata/guard/main_test.go contains the one-line package setup:
	// func TestMain(m *testing.M) { os.Exit(embargotest.Guard(m)) }
	// Run that real test package; it also exercises ordinary parallel tests.
	passed := runExample(func(tb testing.TB) bool {
		tb.Helper()
		cmd := exec.CommandContext(tb.Context(), "go", "test", "./testdata/guard")
		cmd.Env = append(os.Environ(), "GUARD_CASE=safe")
		return cmd.Run() == nil
	})
	fmt.Println(passed)
	// Output: true
}
