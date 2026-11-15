package embargotest_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

// runExample obtains a real testing.TB for executable godoc examples.
// Application tests simply pass their *testing.T to New.
func runExample(f func(testing.TB) bool) bool {
	passed := false
	testing.Benchmark(func(b *testing.B) { b.Helper(); passed = f(b) })
	return passed
}

func show(passed bool) {
	//nolint:forbidigo // The example or isolated child deliberately writes to captured stdout.
	//nolint:forbidigo // Isolated child output is the behavior under test.
	if _, err := fmt.Println(passed); err != nil {
		panic(err)
	}
}

func ExampleNew() {
	passed := false
	testing.Benchmark(func(b *testing.B) {
		b.Helper()
		recorder := embargotest.New(b)
		logger := slog.New(slog.NewJSONHandler(recorder.Writer("logs"), nil))
		logger.Info("accepted", "key", embargo.NewSecret(recorder.Canary()))
		//nolint:goconst // Self-contained examples show the actual display contract.
		recorder.ExpectJSON("logs", nil, map[string]string{"key": "[REDACTED]"}, 1)
		passed = recorder.Check()
	})

	if _, err := fmt.Println(passed); err != nil {
		panic(err)
	}

	// Output: true
}

// begin leaktest

func TestSigningFailureKeepsTheKeySecret(t *testing.T) {
	t.Parallel()
	r := embargotest.New(t)
	key := embargo.NewSecret(r.Canary()) // a fake key the recorder can recognize
	logger := slog.New(slog.NewJSONHandler(r.Writer("logs"), nil))

	logger.Error("signing failed", "key", key)

	r.Expect("logs", func(b []byte) bool { return bytes.Contains(b, []byte(`"key":"[REDACTED]"`)) })
	r.Check()
}

// end leaktest

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
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb, embargotest.WithCanary([]byte("public-fake-canary-0123456789")))
		r.Expect("out", func(data []byte) bool { return string(data) == "[REDACTED]" })
		if _, err := fmt.Fprint(r.Writer("out"), embargo.NewSecret(r.Canary())); err != nil {
			panic(err)
		}
		return r.Check()
	}))
	// Output: true
}

func ExampleWithLimits() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb, embargotest.WithLimits(4096, time.Second))
		r.Expect("out", func(data []byte) bool { return string(data) == "ok" })
		if _, err := fmt.Fprint(r.Writer("out"), "ok"); err != nil {
			panic(err)
		}
		return r.Check()
	}))
	// Output: true
}

func ExampleRecorder_ExpectJSON() {
	show(runExample(func(tb testing.TB) bool {
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
	show(runExample(func(tb testing.TB) bool {
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
	//nolint:forbidigo // Isolated child output is the behavior under test.
	if _, err := fmt.Println("public operation completed"); err != nil {
		panic(err)
	}
}

func ExampleRecorder_Run() {
	show(runExample(func(tb testing.TB) bool {
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

func TestPanicGoldenHelper(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") != "TestPanicGoldenHelper" {
		return
	}
	panic(embargo.NewSecret([32]byte{65, 66, 67}))
}

func TestPanicGolden(t *testing.T) {
	t.Parallel()
	version := strings.Split(strings.TrimPrefix(runtime.Version(), "go"), ".")
	if len(version) < 2 {
		t.Fatal("unknown Go version")
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "panic-go"+version[0]+"."+version[1]+".golden"))
	if err != nil {
		t.Fatal("panic golden missing for this Go line")
	}
	r := embargotest.New(t)
	r.Expect("stderr", func(data []byte) bool {
		header, _, ok := bytes.Cut(data, []byte("\n\n"))
		return ok && bytes.Equal(append(header, '\n'), golden) && bytes.Contains(data, []byte("goroutine "))
	})
	if err := r.Run(context.Background(), "TestPanicGoldenHelper", 2); err != nil {
		t.Fatal("panic helper incomplete")
	}
	r.Check()
}

// begin child

func TestChildRequest(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_TEST_CHILD") == "TestChildRequest" {
		//nolint:forbidigo // Isolated child output is the behavior under test.
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

// end child

func ExampleRecorder() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)
		if _, err := fmt.Fprint(recorder.Writer("out"), "accepted"); err != nil {
			panic(err)
		}
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleOption() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		options := []embargotest.Option{embargotest.WithLimits(4096, time.Second)}
		recorder := embargotest.New(tb, options...)
		if _, err := fmt.Fprint(recorder.Writer("out"), "accepted"); err != nil {
			panic(err)
		}
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleRecorder_Canary() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)
		if _, err := fmt.Fprint(recorder.Writer("out"), embargo.NewSecret(recorder.Canary())); err != nil {
			panic(err)
		}
		recorder.Expect("out", func(data []byte) bool { return string(data) == "[REDACTED]" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleRecorder_Writer() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)
		output := recorder.Writer("out")
		if _, err := fmt.Fprint(output, "accep"); err != nil {
			panic(err)
		}
		if _, err := fmt.Fprint(output, "ted"); err != nil {
			panic(err)
		}
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleRecorder_Expect() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)
		if _, err := fmt.Fprint(recorder.Writer("out"), "accepted"); err != nil {
			panic(err)
		}
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleRecorder_Check() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb)
		if _, err := fmt.Fprint(recorder.Writer("out"), "accepted"); err != nil {
			panic(err)
		}
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleWithScanner() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb, embargotest.WithScanner(embargo.NewScanner(embargo.WithKinds(embargo.KindPAN))))
		if _, err := fmt.Fprint(recorder.Writer("out"), "accepted"); err != nil {
			panic(err)
		}
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleWithAllowedKinds() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb, embargotest.WithAllowedKinds(embargo.KindEmail))
		if _, err := fmt.Fprint(recorder.Writer("out"), "alice@example.com"); err != nil {
			panic(err)
		}
		recorder.Expect("out", func(data []byte) bool { return string(data) == "alice@example.com" })
		return recorder.Check()
	}))

	// Output: true
}

func ExampleWithAllowedValues() {
	show(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb, embargotest.WithAllowedValues("alice@example.com"))
		if _, err := fmt.Fprint(recorder.Writer("out"), "alice@example.com"); err != nil {
			panic(err)
		}
		recorder.Expect("out", func(data []byte) bool { return string(data) == "alice@example.com" })
		return recorder.Check()
	}))

	// Output: true
}
