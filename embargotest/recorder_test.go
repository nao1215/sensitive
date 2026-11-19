package embargotest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nao1215/embargo"
)

type probeTB struct {
	testing.TB

	cleanups []func()
	messages []string
	errors   int
}

func (t *probeTB) Error(args ...any) {
	t.errors++
	t.messages = append(t.messages, fmt.Sprint(args...))
}
func (t *probeTB) Cleanup(f func()) { t.cleanups = append(t.cleanups, f) }
func (t *probeTB) finish() {
	for _, v := range slices.Backward(t.cleanups) {
		v()
	}
}

func write(t *testing.T, r *Recorder, name string, data []byte) {
	t.Helper()
	n, err := r.Writer(name).Write(data)
	if err != nil || n != len(data) {
		t.Fatal("write contract changed")
	}
}

func TestRecorderDefaults(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p, nil)
	if len(r.Canary()) != 32 || r.policy.maxBytes != 1<<20 || r.policy.timeout != 5*time.Second || maxSinks != 16 || childWaitDelay != 250*time.Millisecond {
		t.Fatal("defaults changed")
	}
	c := r.Canary()
	c[0]++
	if bytes.Equal(c, r.Canary()) {
		t.Fatal("canary alias")
	}
	write(t, r, "out", []byte("ok"))
	r.Expect("out", func(data []byte) bool { return string(data) == "ok" })
	for range 2 {
		if !r.Check() {
			t.Fatal("complete observation rejected")
		}
	}
	p.finish()
	if p.errors != 0 {
		t.Fatal("cleanup rejected complete observation")
	}
}

func TestRecorderFailureStates(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*Recorder){
		//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
		"missing":         func(r *Recorder) { r.Expect("missing", func([]byte) bool { return true }) },
		"no-expectations": func(r *Recorder) { write(t, r, "out", []byte("ok")) },
		"false": func(r *Recorder) {
			write(t, r, "out", []byte("ok"))
			r.Expect("out", func([]byte) bool { return false })
		},
		"panic": func(r *Recorder) {
			write(t, r, "out", []byte("ok"))
			r.Expect("out", func([]byte) bool { panic(string(r.Canary())) })
		},
		"nil":        func(r *Recorder) { r.Expect("out", nil) },
		"empty-name": func(r *Recorder) { write(t, r, "", nil) },
		"long-name":  func(r *Recorder) { write(t, r, strings.Repeat("x", 129), nil) },
		"sink-limit": func(r *Recorder) {
			for i := range 17 {
				write(t, r, strconv.Itoa(i), nil)
			}
		},
		"limit": func(r *Recorder) {
			write(t, r, "out", bytes.Repeat([]byte("x"), int(defaultMaxBytes)+1))
			r.Expect("out", func([]byte) bool { return true })
		},
		"leak-split": func(r *Recorder) {
			write(t, r, "out", r.Canary()[:10])
			write(t, r, "out", r.Canary()[10:])
			r.Expect("out", func([]byte) bool { return true })
		},
		//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
		"running": func(r *Recorder) {
			r.running = 1
			write(t, r, "out", []byte("ok"))
			r.Expect("out", func([]byte) bool { return true })
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := &probeTB{TB: t}
			r := New(p)
			f(r)
			if r.Check() {
				t.Fatal("incomplete observation passed")
			}
			p.finish()
			if p.errors == 0 {
				t.Fatal("missing test error")
			}
			for _, s := range p.messages {
				if strings.Contains(s, string(r.Canary())) {
					t.Fatal("failure report leaked payload")
				}
			}
		})
	}
}

func TestRecorderLifecycle(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"unchecked", "late-write", "late-writer", "late-expect"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			p := &probeTB{TB: t}
			r := New(p)
			w := r.Writer("out")
			write(t, r, "out", []byte("ok"))
			r.Expect("out", func([]byte) bool { return true })
			if mode != "unchecked" {
				if !r.Check() {
					t.Fatal("initial check failed")
				}
			}
			switch mode {
			case "late-write":
				if _, err := w.Write([]byte("late")); err != nil {
					t.Fatal(err)
				}
			case "late-writer":
				r.Writer("late")
			case "late-expect":
				r.Expect("out", func([]byte) bool { return true })
			}
			p.finish()
			if p.errors == 0 {
				t.Fatal("cleanup missed state failure")
			}
		})
	}
}

func TestRecorderOptions(t *testing.T) {
	t.Parallel()
	for _, option := range []Option{WithCanary(make([]byte, 15)), WithCanary(make([]byte, 1025)), WithMaxBytes(0), WithMaxBytes(-1), WithTimeout(0), WithTimeout(-time.Second)} {
		p := &probeTB{TB: t}
		r := New(p, option)
		if p.errors == 0 {
			t.Fatal("constructor did not report invalid options")
		}
		if r.Check() || p.errors == 0 {
			t.Fatal("invalid option accepted")
		}
		p.finish()
	}
	for _, size := range []int{16, 1024} {
		c := bytes.Repeat([]byte("x"), size)
		o := WithCanary(c)
		c[0] = 'y'
		p := &probeTB{TB: t}
		r := New(p, o, WithMaxBytes(1), WithTimeout(time.Nanosecond))
		if r.Canary()[0] != 'x' {
			t.Fatal("option aliases input")
		}
		write(t, r, "a", []byte("a"))
		r.Expect("a", func(b []byte) bool { return string(b) == "a" })
		if !r.Check() {
			t.Fatal("positive limit rejected")
		}
		p.finish()
	}
}

func TestRecorderConcurrentWrites(t *testing.T) {
	t.Parallel()
	r := New(t)
	w := r.Writer("out")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				if _, err := w.Write([]byte("x")); err != nil {
					t.Error("write failed")
				}
			}
		})
	}
	wg.Wait()
	r.Expect("out", func(b []byte) bool { return len(b) == 800 })
	r.Check()
}

func TestRecorderValidatorCopies(t *testing.T) {
	t.Parallel()
	r := New(t)
	write(t, r, "out", []byte("ok"))
	r.Expect("out", func(b []byte) bool { b[0] = 'x'; return true })
	r.Expect("out", func(b []byte) bool { return string(b) == "ok" })
	r.Check()
}

func TestRecorderExactBoundaries(t *testing.T) {
	t.Parallel()
	r := New(t)
	for i := range 16 {
		name := fmt.Sprintf("%0128d", i)
		write(t, r, name, []byte("ok"))
		r.Expect(name, func(b []byte) bool { return string(b) == "ok" })
	}
	r.Check()
	for _, name := range []string{"", strings.Repeat("a", 129)} {
		p := &probeTB{TB: t}
		r := New(p)
		r.Expect(name, func([]byte) bool { return true })
		if !r.failed {
			t.Fatal("invalid expectation name accepted")
		}
		r.Check()
		p.finish()
	}
}

func TestSeventeenthSinkRejectedWithExpectations(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p)
	for i := range 17 {
		name := strconv.Itoa(i)
		write(t, r, name, []byte("ok"))
		r.Expect(name, func(b []byte) bool { return string(b) == "ok" })
	}
	if r.Check() {
		t.Fatal("seventeenth sink accepted")
	}
	p.finish()
}

func TestRecorderReportsFixedReasonsOnce(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		run  func(*Recorder)
		want string
	}{
		//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
		"leak": {func(r *Recorder) {
			write(t, r, "logs", append([]byte("signing failed "), r.Canary()...))
			r.Expect("logs", func(data []byte) bool { return bytes.Contains(data, []byte("signing failed")) })
			//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
		}, "embargotest: the fake secret appeared in captured output: logs"},
		"expectation": {func(r *Recorder) {
			write(t, r, "logs", []byte("ok"))
			r.Expect("logs", func([]byte) bool { return false })
		}, unmetExpectation},
		"empty":                    {func(*Recorder) {}, noExpectation},
		"sink without expectation": {func(r *Recorder) { r.Writer("logs") }, noExpectation},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := &probeTB{TB: t}
			r := New(p)
			tc.run(r)
			if r.Check() {
				t.Fatal("failure accepted")
			}
			p.finish()
			if len(p.messages) != 1 || p.messages[0] != tc.want {
				t.Fatalf("messages = %q", p.messages)
			}
			for _, m := range p.messages {
				if strings.Contains(m, string(r.Canary())) {
					t.Fatal("payload reflected")
				}
			}
		})
	}
}

// Fixed Check reasons shared by the recorder tests.
const (
	unmetExpectation = "embargotest: a content expectation was not met"
	noExpectation    = "embargotest: no output or no content expectation was registered"
)

func TestRecorderExpectationWithoutSink(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p)
	r.Expect("logs", func([]byte) bool { return true })
	if r.Check() {
		t.Fatal("an expectation without any sink was accepted")
	}
	p.finish()
	want := []string{noExpectation, unmetExpectation}
	if !slices.Equal(p.messages, want) {
		t.Fatalf("messages = %q, want %q", p.messages, want)
	}
}

func TestRecorderCleanupReportsLateChange(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p)
	write(t, r, "out", []byte("ok"))
	r.Expect("out", func(data []byte) bool { return string(data) == "ok" })
	if !r.Check() {
		t.Fatal("complete observation rejected")
	}
	_, _ = r.Writer("out").Write([]byte("late")) //nolint:errcheck // The late write is the behavior under test.
	p.finish()
	if len(p.messages) != 1 || p.messages[0] != "embargotest: output or registration changed after Check" {
		t.Fatalf("messages = %q", p.messages)
	}
}

func TestQuintRecorderReplay(t *testing.T) {
	t.Parallel()
	for _, trace := range modelTraces[recorderState](t, "recorder") {
		probe := &probeTB{TB: t}
		recorder := New(probe, WithMaxBytes(4), WithTimeout(time.Second), WithScanner(embargo.NewScanner(embargo.WithKinds())))
		for _, state := range trace {
			switch state.Op {
			case "init":
			case "write":
				if _, err := io.WriteString(recorder.Writer(strconv.Itoa(state.Which)), "x"); err != nil {
					t.Fatal(err)
				}
			case "expect":
				recorder.Expect(strconv.Itoa(state.Which), func([]byte) bool { return true })
			case "check":
				if recorder.Check() == state.Failed {
					t.Fatal("Check disagrees with model")
				}
			case "cleanup":
				probe.finish()
			default:
				t.Fatal("unknown model operation")
			}
			if recorder.retained != int64(state.Size) || recorder.checked != state.Checked || recorder.failed != state.Failed || recorder.reported != state.Reported || (probe.errors > 0) != (state.Errors > 0) {
				t.Fatalf("state mismatch after %s: model=%+v", state.Op, state)
			}
			for _, w := range []int{0, 1} {
				_, got := recorder.sinks[strconv.Itoa(w)]
				if got != slices.Contains(state.Writers, w) {
					t.Fatal("writer registration changed")
				}
			}
		}
	}
}

//nolint:tagliatelle // Quint trace field names are the external schema.
type guardState struct {
	Op            string `json:"op"`
	Sizes         []int  `json:"sizes"`
	Leaks         []int  `json:"leaks"`
	Replay        []int  `json:"replay"`
	Phase         int    `json:"phase"`
	Overflow      bool   `json:"overflow"`
	Timeout       bool   `json:"timeout"`
	ScannerFailed bool   `json:"scannerFailed"`
	ExitFailed    bool   `json:"exitFailed"`
	Code          int    `json:"code"`
	Which         int    `json:"which"`
}

// Child mode uses real OS pipes but exits before the testing runner prints its
// own framing, so one modeled chunk corresponds to exactly 32 captured bytes.
//

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
	r := New(t)
	r.Expect("stderr", func(data []byte) bool {
		header, _, ok := bytes.Cut(data, []byte("\n\n"))
		return ok && bytes.Equal(append(header, '\n'), golden) && bytes.Contains(data, []byte("goroutine "))
	})
	if err := r.Run(context.Background(), "TestPanicGoldenHelper", 2); err != nil {
		t.Fatal("panic helper incomplete")
	}
	r.Check()
}

func TestRecorderRejectsRegistrationDuringValidation(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p)
	write(t, r, "out", []byte("ok"))
	r.Expect("out", func(data []byte) bool {
		// A validator runs outside the lock; a competing registration must remain sticky.
		done := make(chan struct{})
		go func() { r.Writer("late"); close(done) }()
		<-done
		return string(data) == "ok"
	})
	if r.Check() || p.errors != 1 || !strings.Contains(p.messages[0], "changed during Check") {
		t.Fatal("registration race was not rejected")
	}
	p.finish()
}
