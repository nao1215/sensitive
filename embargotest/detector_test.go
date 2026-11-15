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
				if strings.Contains(message, tc.text) || strings.Contains(message, "private-sink-name") {
					t.Fatal("failure reflected captured text or sink name")
				}
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
	recorder := New(probe, WithLimits(256, time.Second))
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
