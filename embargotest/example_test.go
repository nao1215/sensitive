package embargotest_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

func ExampleNew() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)
		logger := slog.New(slog.NewJSONHandler(recorder.Writer("logs"), nil))
		logger.Info("accepted", "key", embargo.NewSecret(recorder.Canary()))
		//nolint:goconst // Self-contained examples show the actual display contract.
		recorder.ExpectJSON("logs", nil, map[string]string{"key": "[REDACTED]"}, 1)
		return recorder.Check()
	}))

	// Output: true
}

func TestSigningFailureKeepsTheKeySecret(t *testing.T) {
	t.Parallel()
	r := embargotest.New(t)
	key := embargo.NewSecret(r.Canary()) // a fake key the recorder can recognize
	logger := slog.New(slog.NewJSONHandler(r.Writer("logs"), nil))

	logger.Error("signing failed", "key", key)

	r.Expect("logs", func(b []byte) bool { return bytes.Contains(b, []byte(`"key":"[REDACTED]"`)) })
	r.Check()
}

func TestRecorderExample(t *testing.T) {
	t.Parallel()
	// begin recorder
	r := embargotest.New(t)
	//nolint:goconst // Self-contained examples keep their expected output local.
	r.Expect("response", func(b []byte) bool { return string(b) == "accepted" })
	if _, err := fmt.Fprint(r.Writer("response"), "accepted"); err != nil {
		panic(err)
	}
	r.Check()
	// end recorder
}

func ExampleWithCanary() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb, embargotest.WithCanary([]byte("public-fake-canary-0123456789")))
		r.Expect("out", func(data []byte) bool { return string(data) == "[REDACTED]" })

		fmt.Fprint(r.Writer("out"), embargo.NewSecret(r.Canary()))
		return r.Check()
	}))

	// Output: true
}

func ExampleWithMaxBytes() {
	write := func(tb testing.TB, text string) bool {
		tb.Helper()
		r := embargotest.New(tb, embargotest.WithMaxBytes(16))
		r.Expect("out", func(data []byte) bool { return len(data) > 0 })
		fmt.Fprint(r.Writer("out"), text)
		return r.Check()
	}

	fmt.Println(runExample(func(tb testing.TB) bool { tb.Helper(); return write(tb, "sixteen bytes ok") }))
	fmt.Println(runExample(func(tb testing.TB) bool { tb.Helper(); return write(tb, "seventeen bytes!!") }))

	// Output:
	// true
	// false
}

func ExampleWithTimeout() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		// TestChildHang waits a minute; the recorder stops it after 100 ms.
		r := embargotest.New(tb, embargotest.WithTimeout(100*time.Millisecond))
		err := r.Run(context.Background(), "TestChildHang", 0)
		return err == nil && r.Check()
	}))

	// Output: false
}

func ExampleRecorder_ExpectJSON() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb)
		logger := slog.New(slog.NewJSONHandler(r.Writer("logs"), nil))

		logger.Error("request failed", "code", "signing_failed")

		r.ExpectJSON("logs", nil, map[string]string{"msg": "request failed", "code": "signing_failed"}, 1)
		return r.Check()
	}))

	// Output: true
}

func ExampleRecorder_HTTP() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb)
		response := r.HTTP("response")
		response.Header().Set("X-Result", "accepted")
		response.WriteHeader(http.StatusAccepted)
		r.Expect("response/status", func(data []byte) bool { return string(data) == "202" })
		return r.Check()
	}))

	// Output: true
}

func TestExampleChild(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestExampleChild" {
		return
	}
	if _, err := fmt.Println("public operation completed"); err != nil {
		panic(err)
	}
}

func ExampleRecorder_Run() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb)
		r.Expect("stdout", func(data []byte) bool { return bytes.Contains(data, []byte("public operation completed")) })
		if err := r.Run(context.Background(), "TestExampleChild", 0); err != nil {
			tb.Fatal("child failed")
		}
		return r.Check()
	}))

	// Output: true
}

func TestChildRequest(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") == "TestChildRequest" {
		if _, err := fmt.Println("request rejected"); err != nil {
			panic(err)
		}
		return
	}

	r := embargotest.New(t)
	r.Expect("stdout", func(data []byte) bool { return bytes.Contains(data, []byte("request rejected")) })
	if err := r.Run(context.Background(), "TestChildRequest", 0); err != nil {
		t.Fatal("child incomplete")
	}
	r.Check()
}

func ExampleRecorder() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)

		fmt.Fprint(recorder.Writer("out"), "accepted")
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleOption() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		options := []embargotest.Option{embargotest.WithMaxBytes(4096), embargotest.WithTimeout(time.Second)}
		recorder := embargotest.New(tb, options...)

		fmt.Fprint(recorder.Writer("out"), "accepted")
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleRecorder_Canary() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)

		fmt.Fprint(recorder.Writer("out"), embargo.NewSecret(recorder.Canary()))
		recorder.Expect("out", func(data []byte) bool { return string(data) == "[REDACTED]" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleRecorder_Writer() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)
		output := recorder.Writer("out")

		fmt.Fprint(output, "accep")

		fmt.Fprint(output, "ted")
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleRecorder_Expect() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)

		fmt.Fprint(recorder.Writer("out"), "accepted")
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleRecorder_Check() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)

		fmt.Fprint(recorder.Writer("out"), "accepted")
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleWithScanner() {
	logEmail := func(tb testing.TB, opts ...embargotest.Option) bool {
		tb.Helper()
		r := embargotest.New(tb, opts...)
		r.Expect("out", func(data []byte) bool { return len(data) > 0 })
		fmt.Fprint(r.Writer("out"), "sent to alice@example.com")
		return r.Check()
	}
	cardsOnly := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN))

	// The default scanner fails on the email address; a card-only scanner allows it.
	fmt.Println(runExample(func(tb testing.TB) bool { tb.Helper(); return logEmail(tb) }))
	fmt.Println(runExample(func(tb testing.TB) bool { tb.Helper(); return logEmail(tb, embargotest.WithScanner(cardsOnly)) }))

	// Output:
	// false
	// true
}

func ExampleWithAllowedKinds() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb, embargotest.WithAllowedKinds(embargo.KindEmail))

		fmt.Fprint(recorder.Writer("out"), "alice@example.com")
		recorder.Expect("out", func(data []byte) bool { return string(data) == "alice@example.com" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleWithAllowedValues() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb, embargotest.WithAllowedValues("alice@example.com"))

		fmt.Fprint(recorder.Writer("out"), "alice@example.com")
		recorder.Expect("out", func(data []byte) bool { return string(data) == "alice@example.com" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleWithCanaryFragments() {
	logPrefix := func(tb testing.TB, opts ...embargotest.Option) bool {
		tb.Helper()
		r := embargotest.New(tb, opts...)
		r.Expect("logs", func(data []byte) bool { return len(data) > 0 })
		// The code under test logs the first 16 bytes of the secret.
		fmt.Fprintf(r.Writer("logs"), "token prefix %s", r.Canary()[:16])
		return r.Check()
	}

	fmt.Println(runExample(func(tb testing.TB) bool { tb.Helper(); return logPrefix(tb) }))
	fmt.Println(runExample(func(tb testing.TB) bool { tb.Helper(); return logPrefix(tb, embargotest.WithCanaryFragments(16)) }))

	// Output:
	// true
	// false
}

func ExampleCheckValue() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		return embargotest.CheckValue(tb, func(canary string) any { return embargo.NewSecret(canary) })
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

// This example preserves an application's existing key-based masking. Only the
// test recorder comes from embargotest; it does not replace the masking policy.
func ExampleRecorder_existingMasking() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)
		existing := &slog.HandlerOptions{ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == "token" {
				return slog.String(attr.Key, "[REDACTED]")
			}
			return attr
		}}
		logger := slog.New(slog.NewJSONHandler(recorder.Writer("logs"), existing))
		logger.Info("accepted", "token", string(recorder.Canary()))
		recorder.ExpectJSON("logs", nil, map[string]string{"msg": "accepted", "token": "[REDACTED]"}, 1)
		return recorder.Check()
	}))
	// Output: true
}
