package embargotest

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/embargo"
)

func TestEmptyRegisteredStreamCannotPass(t *testing.T) {
	t.Parallel()
	probe := &probeTB{TB: t}
	recorder := New(probe)
	recorder.Writer("registered")
	recorder.Expect("registered", func([]byte) bool { return true })
	if recorder.Check() {
		t.Fatal("a registered stream without logged bytes passed")
	}
	probe.finish()
}

func TestDetectorPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		text string
		opts []Option
		pass bool
	}{
		//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
		{name: "default detects email", text: "alice@example.com"},
		{name: "kind allowance", opts: []Option{WithAllowedKinds(embargo.KindEmail)}, text: "alice@example.com", pass: true},
		{name: "exact value allowance", opts: []Option{WithAllowedValues("alice@example.com")}, text: "alice@example.com", pass: true},
		{name: "value is case sensitive", opts: []Option{WithAllowedValues("ALICE@example.com")}, text: "alice@example.com"},
		{name: "selected scanner", opts: []Option{WithScanner(embargo.NewScanner(embargo.WithKinds(embargo.KindPAN)))}, text: "alice@example.com", pass: true},
		//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
		{name: "nil scanner", opts: []Option{WithScanner(nil)}, text: "accepted"},
		{name: "empty kind", opts: []Option{WithAllowedKinds("")}, text: "accepted"},
		{name: "empty value", opts: []Option{WithAllowedValues("")}, text: "accepted"},
		{name: "canary cannot be allowed", opts: []Option{WithAllowedValues(defaultCanary)}, text: defaultCanary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &probeTB{TB: t}
			r := New(p, tc.opts...)
			write(t, r, "private-sink-name", []byte(tc.text))
			r.Expect("private-sink-name", func(data []byte) bool { return string(data) == tc.text })
			if r.Check() != tc.pass {
				t.Fatal("unexpected detector verdict")
			}
			p.finish()
			for _, message := range p.messages {
				if strings.Contains(message, tc.text) {
					t.Fatal("failure reflected captured text")
				}
			}
			if !tc.pass && tc.text != "accepted" && !strings.Contains(strings.Join(p.messages, "\n"), "private-sink-name") {
				t.Fatalf("failure did not name the sink: %q", p.messages)
			}
		})
	}
}

type overlapDetector struct{}

func (overlapDetector) Scan(data []byte) []embargo.Finding {
	return []embargo.Finding{{Kind: "custom", Start: 0, End: len(data), Confidence: 1}}
}

type panicDetector struct{}

func (panicDetector) Scan([]byte) []embargo.Finding { panic("private-panic-text") }

func TestDetectorOverlapAndPanic(t *testing.T) {
	t.Parallel()
	for _, custom := range []embargo.Detector{overlapDetector{}, panicDetector{}} {
		p := &probeTB{TB: t}
		r := New(p, WithScanner(embargo.NewScanner(embargo.WithKinds(embargo.KindEmail), embargo.WithDetector(custom))), WithAllowedKinds(embargo.KindEmail))
		write(t, r, "out", []byte("alice@example.com"))
		r.Expect("out", func([]byte) bool { return true })
		if r.Check() {
			t.Fatal("allowed email hid a different overlapping finding or scanner failure")
		}
		p.finish()
		for _, message := range p.messages {
			if strings.Contains(message, "private-panic-text") {
				t.Fatal("scanner panic leaked")
			}
		}
	}
}

func TestDetectorSeesInformationalHeaders(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p)
	w := r.HTTP("response")
	w.Header().Set("X-Contact", "alice@example.com")
	w.WriteHeader(http.StatusEarlyHints)
	w.Header().Del("X-Contact")
	w.WriteHeader(http.StatusOK)
	r.Expect("response/status", func(data []byte) bool { return string(data) == "200" })
	if r.Check() {
		t.Fatal("informational header escaped detector check")
	}
	p.finish()
}

func TestInformationalHeadersConsumeTotalBudget(t *testing.T) {
	t.Parallel()
	probe := &probeTB{TB: t}
	recorder := New(probe, WithMaxBytes(256), WithTimeout(time.Second))
	response := recorder.HTTP("response")
	response.Header().Set("X-Result", strings.Repeat("x", 80))
	for range 4 {
		response.WriteHeader(http.StatusEarlyHints)
	}
	response.Header().Del("X-Result")
	response.WriteHeader(http.StatusOK)
	recorder.Expect("response/status", func(data []byte) bool { return string(data) == "200" })
	if recorder.Check() {
		t.Fatal("repeated interim output exceeded the total budget but passed")
	}
	probe.finish()
}

type nilPanicDetector struct{}

//nolint:govet // Exercise pre-Go-1.21 nil-panic recovery under GODEBUG=panicnil=1.
func (nilPanicDetector) Scan([]byte) []embargo.Finding { panic(nil) }

func TestNilPanicCompatibility(t *testing.T) {
	t.Setenv("GODEBUG", "panicnil=1")
	const validator = "validator"
	//nolint:paralleltest // Parent changes process-global GODEBUG; keep these subtests sequential.
	for _, kind := range []string{"scanner", validator} {
		t.Run(kind, func(t *testing.T) {
			probe := &probeTB{TB: t}
			scanner := embargo.NewScanner(embargo.WithKinds())
			if kind == "scanner" {
				scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(nilPanicDetector{}))
			}
			recorder := New(probe, WithScanner(scanner))
			write(t, recorder, "out", []byte("accepted"))
			recorder.Expect("out", func([]byte) bool {
				if kind == validator {
					panic(nil) //nolint:govet // Verify expectation failure in nil-panic compatibility mode.
				}
				return true
			})
			if recorder.Check() {
				t.Fatal("panic(nil) was accepted as a completed check")
			}
			probe.finish()
			want := "embargotest: scanner failed"
			if kind == validator {
				want = "embargotest: a content expectation was not met"
			}
			if len(probe.messages) != 1 || probe.messages[0] != want {
				t.Fatal("panic(nil) must produce only the fixed failure message")
			}
		})
	}
}

func TestDefaultRecorderExcludesOptInKinds(t *testing.T) {
	t.Parallel()
	const data = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW 123-45-6789"
	for _, all := range []bool{false, true} {
		probe := &probeTB{TB: t}
		var options []Option
		if all {
			options = append(options, WithScanner(embargo.NewScanner(embargo.WithAll())))
		}
		recorder := New(probe, options...)
		write(t, recorder, "defaults", []byte(data))
		recorder.Expect("defaults", func(actual []byte) bool { return string(actual) == data })
		if recorder.Check() == all {
			t.Fatalf("all=%t returned the wrong default verdict", all)
		}
		probe.finish()
	}
}

// otherAddressLine is captured output with an address that differs from the sink name.
const otherAddressLine = "user bob@example.com"

// unprintableSinkFailure is the failure for an email under a rejected sink name.
const unprintableSinkFailure = "embargotest: sensitive data appeared in captured output: a sink with an unprintable name (email)"

func TestFailureNamesSinkAndKindWithoutData(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, sink, text, want string
	}{
		{"finding", "app.log", "user alice@example.com", "embargotest: sensitive data appeared in captured output: app.log (email)"},
		{"sink name with a finding", "alice@example.com", otherAddressLine, unprintableSinkFailure},
		{"sink name with spaces", "my sink", otherAddressLine, unprintableSinkFailure},
		{"long sink name", strings.Repeat("s", 65), otherAddressLine, unprintableSinkFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &probeTB{TB: t}
			r := New(p)
			write(t, r, tc.sink, []byte(tc.text))
			r.Expect(tc.sink, func([]byte) bool { return true })
			if r.Check() {
				t.Fatal("finding accepted")
			}
			p.finish()
			if len(p.messages) != 1 || p.messages[0] != tc.want {
				t.Fatalf("messages = %q, want %q", p.messages, tc.want)
			}
		})
	}
	t.Run("canary in the sink name", func(t *testing.T) {
		t.Parallel()
		p := &probeTB{TB: t}
		r := New(p)
		sink := string(r.Canary())
		write(t, r, sink, r.Canary())
		r.Expect(sink, func([]byte) bool { return true })
		r.Check()
		p.finish()
		if joined := strings.Join(p.messages, "\n"); strings.Contains(joined, sink) || !strings.Contains(joined, "a sink with an unprintable name") {
			t.Fatalf("messages = %q", p.messages)
		}
	})
}

type spacedKindDetector struct{}

func (spacedKindDetector) Scan(data []byte) []embargo.Finding {
	if string(data) != "opaque fixture" {
		return nil
	}
	return []embargo.Finding{{Kind: "my kind", Start: 0, End: len(data), Confidence: 1}}
}

func TestFailureReplacesAnUnprintableKind(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p, WithScanner(embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(spacedKindDetector{}))))
	write(t, r, "app.log", []byte("opaque fixture"))
	r.Expect("app.log", func([]byte) bool { return true })
	r.Check()
	p.finish()
	if want := "embargotest: sensitive data appeared in captured output: app.log (custom kind)"; len(p.messages) != 1 || p.messages[0] != want {
		t.Fatalf("messages = %q, want %q", p.messages, want)
	}
}
