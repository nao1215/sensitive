//nolint:goconst // Runnable examples are self-contained and show the literal marker.
package embargotest_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

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
	// Create a complete test file, so this example needs no repository fixtures.
	dir, err := os.MkdirTemp(".", ".embargo-guard-example-")
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			panic(err)
		}
	}()
	path := filepath.Join(dir, "main_test.go")
	source := `package guarded_test
import (
 "os"
 "testing"
 "github.com/nao1215/embargo"
 "github.com/nao1215/embargo/embargotest"
)
func TestMain(m *testing.M) { os.Exit(embargotest.Guard(m)) }
func TestOutput(t *testing.T) {
 t.Parallel()
 t.Log(embargo.NewSecret("opaque-example-value"))
}
`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "main_test.go")
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		panic(string(output))
	}
	fmt.Println(true)
	// Output: true
}

// runExample obtains a real testing.TB for executable godoc examples.
// Application tests simply pass their *testing.T to New.
func runExample(f func(testing.TB) bool) bool {
	passed := false
	testing.Benchmark(func(b *testing.B) { b.Helper(); passed = f(b) })
	return passed
}
