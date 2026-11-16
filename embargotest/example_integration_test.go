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

	fmt.Println(passed)

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
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb, embargotest.WithCanary([]byte("public-fake-canary-0123456789")))
		r.Expect("out", func(data []byte) bool { return string(data) == "[REDACTED]" })

		fmt.Fprint(r.Writer("out"), embargo.NewSecret(r.Canary()))
		return r.Check()
	}))

	// Output: true
}

func ExampleWithLimits() {
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb, embargotest.WithLimits(4096, time.Second))
		r.Expect("out", func(data []byte) bool { return string(data) == "ok" })

		fmt.Fprint(r.Writer("out"), "ok")
		return r.Check()
	}))

	// Output: true
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
		options := []embargotest.Option{embargotest.WithLimits(4096, time.Second)}
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
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		recorder := embargotest.New(tb, embargotest.WithScanner(embargo.NewScanner(embargo.WithKinds(embargo.KindPAN))))

		fmt.Fprint(recorder.Writer("out"), "accepted")
		recorder.Expect("out", func(data []byte) bool { return string(data) == "accepted" })
		return recorder.Check()
	}))

	// Output: true
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
	fmt.Println(runExample(func(tb testing.TB) bool {
		tb.Helper()
		r := embargotest.New(tb, embargotest.WithCanaryFragments(16))
		// Preserve useful content; a surviving 16-byte raw fragment would fail Check.
		fmt.Fprint(r.Writer("logs"), "order accepted: ", embargo.NewSecret(r.Canary()))
		r.Expect("logs", func(data []byte) bool { return string(data) == "order accepted: [REDACTED]" })
		return r.Check()
	}))
	// Output: true
}
