package embargotest

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nao1215/embargo"
)

const (
	defaultCanary         = "embargo-fake-secret-0123456789ab"
	defaultMaxBytes int64 = 1 << 20
	defaultTimeout        = 5 * time.Second
	maxSinks              = 16
	maxNameBytes          = 128
	childWaitDelay        = 250 * time.Millisecond
)

// Recorder captures bounded output and checks both secret absence and expected
// content. Writers support concurrent calls. Stop producers before Check.
// Every recorder must be checked; Cleanup reports missing checks and late writes.
type Recorder struct {
	tb            testing.TB
	allowedKinds  map[embargo.Kind]bool
	allowedValues map[string]bool
	sinks         map[string]*stream
	scanner       *embargo.Scanner
	needles       [][]byte
	expectations  []expectation
	responses     []*response
	canary        []byte
	maxBytes      int64
	timeout       time.Duration
	retained      int64
	minFragment   int
	running       int
	mu            sync.Mutex
	scannerFailed bool
	detected      bool
	checked       bool
	failed        bool
	reported      bool
	leaked        bool
}

type stream struct {
	recorder *Recorder
	data     []byte
}
type expectation struct {
	validate func([]byte) bool
	name     string
}

// Option configures a Recorder without exposing mutable configuration.
type (
	Option       interface{ apply(*Recorder) bool }
	canaryOption []byte
	limitsOption struct {
		maxBytes int64
		timeout  time.Duration
	}
)

// WithCanary copies a fake secret of 16 through 1024 bytes. Never use a real
// credential: test inputs and shrinking counterexamples may appear in logs. Use
// distinctive bytes: a mostly zero canary has a short decimal form, such as 0,
// that matches unrelated output.
func WithCanary(canary []byte) Option { return canaryOption(append([]byte(nil), canary...)) }

func (c canaryOption) apply(r *Recorder) bool {
	if len(c) < 16 || len(c) > 1024 {
		return false
	}
	r.canary = append([]byte(nil), c...)
	return true
}

// WithLimits sets positive bounds for total retained output and each Run.
// maxBytes bounds bytes retained across sinks, not bytes allocated or produced
// before a Write. timeout supervises each Run child process, not in-process
// encoding, input decoding or scanner callbacks. MarshalJSON, LogValue, String
// and Error can run in an encoder before this limit applies; their time and
// memory are not bounded. Prefer Secret or a LogValuer returning a bounded value.
// Neither bound can be disabled. The sink count and WaitDelay stay fixed.
func WithLimits(maxBytes int64, timeout time.Duration) Option { return limitsOption{maxBytes, timeout} }

func (o limitsOption) apply(r *Recorder) bool {
	if o.maxBytes < 1 || o.timeout <= 0 {
		return false
	}
	r.maxBytes, r.timeout = o.maxBytes, o.timeout
	return true
}

// New creates a Recorder with a public 32-byte fake canary, 1 MiB total retained
// output, a 5 second run limit, 16 sinks and 250 ms child WaitDelay. Nil options
// do nothing. The default scanner omits unlabelled entropy tokens; use WithScanner to choose kinds. Invalid options fail the test and leave Check unable to succeed.
func New(tb testing.TB, opts ...Option) *Recorder {
	tb.Helper()
	r := &Recorder{minFragment: 0, detected: false, scannerFailed: false, responses: nil, mu: sync.Mutex{}, needles: nil, retained: 0, expectations: nil, checked: false, failed: false, reported: false, leaked: false, running: 0, scanner: embargo.NewScanner(), allowedKinds: map[embargo.Kind]bool{}, allowedValues: map[string]bool{}, tb: tb, canary: []byte(defaultCanary), maxBytes: defaultMaxBytes, timeout: defaultTimeout, sinks: make(map[string]*stream)}
	for _, o := range opts {
		if o != nil && !o.apply(r) {
			r.failed = true
		}
	}
	r.configureNeedles()
	if r.failed {
		tb.Error("embargotest: invalid options")
	}
	tb.Cleanup(func() {
		r.mu.Lock()
		for _, response := range r.responses {
			if response.trailersChanged() {
				r.failed = true
			}
		}
		checked, running, late := r.checked, r.running != 0, r.failed && !r.reported
		r.mu.Unlock()
		switch {
		case !checked:
			tb.Error("embargotest: Check was not called")
		case running:
			tb.Error("embargotest: a Run was still active at cleanup")
		case late:
			tb.Error("embargotest: output or registration changed after Check")
		}
	})
	return r
}

// Canary returns a copy of the fake secret to insert into the tested path.
func (r *Recorder) Canary() []byte { return append([]byte(nil), r.canary...) }

// Writer returns the named stream; repeated calls append to the same capture.
// Names must have 1 through 128 bytes. Writes after Check and truncated output
// cause a sticky failure. Excess output is discarded while writes still drain.
func (r *Recorder) Writer(name string) io.Writer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writer(name)
}

func (r *Recorder) writer(name string) *stream {
	if r.checked || name == "" || len(name) > maxNameBytes {
		r.failed = true
		return &stream{recorder: r}
	}
	if s, ok := r.sinks[name]; ok {
		return s
	}
	if len(r.sinks) >= maxSinks {
		r.failed = true
		return &stream{recorder: r}
	}
	s := &stream{recorder: r}
	r.sinks[name] = s
	return s
}

// Write appends to this sink; late or truncated writes make Check fail.
func (s *stream) Write(p []byte) (int, error) {
	r := s.recorder
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checked {
		r.failed = true
		return len(p), nil
	}
	return r.capture(s, p)
}

// capture appends while the caller holds mu.
func (r *Recorder) capture(s *stream, p []byte) (int, error) {
	if r.checked {
		r.failed = true
		return len(p), nil
	}
	remaining := r.maxBytes - r.retained
	keep := len(p)
	if int64(keep) > remaining {
		keep = int(remaining)
		r.failed = true
	}
	s.data = append(s.data, p[:keep]...)
	r.retained += int64(keep)
	return len(p), nil
}

// Expect registers a synchronous, terminating validator for a copy of a sink's
// bytes. Panics fail without printing the panic value. Join producers first;
// validators must not call back into or write to this Recorder.
func (r *Recorder) Expect(name string, validate func([]byte) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checked || validate == nil || name == "" || len(name) > maxNameBytes {
		r.failed = true
		return
	}
	r.expectations = append(r.expectations, expectation{name: name, validate: validate})
}

// Check scans every capture for the canary and non-allowed detector findings, then evaluates expectations.
// It never waits for producers. Missing sinks, no expectations, incomplete runs,
// truncation and failed validators report fixed test errors and return false.
func (r *Recorder) Check() bool {
	r.tb.Helper()
	r.mu.Lock()
	for _, response := range r.responses {
		if response.trailersChanged() {
			r.failed = true
		}
		response.finalize()
	}
	r.checked = true
	// Each reason is a fixed sentence: captured bytes and sink names never
	// reach the test log.
	var reasons []string
	interim := make([][]byte, 0, len(r.responses))
	for _, response := range r.responses {
		interim = append(interim, append([]byte(nil), response.interim.data...))
	}
	if r.failed {
		reasons = append(reasons, "observation incomplete: invalid use, truncated output, or a canceled or failed Run")
	}
	if r.running != 0 {
		reasons = append(reasons, "a Run is still active")
	}
	if len(r.sinks) == 0 || len(r.expectations) == 0 {
		reasons = append(reasons, "no output or no content expectation was registered")
	}
	captures := make(map[string][]byte, len(r.sinks))
	observed := false
	for name, s := range r.sinks {
		captures[name] = append([]byte(nil), s.data...)
		observed = observed || len(s.data) > 0
	}
	if !observed && len(r.sinks) > 0 && len(r.expectations) > 0 {
		reasons = append(reasons, "no output was captured")
	}
	expectations := append([]expectation(nil), r.expectations...)
	leaked := r.leaked
	detected, scannerFailed := r.detected, r.scannerFailed
	r.mu.Unlock()
	reasons = append(reasons, r.contentReasons(captures, interim, leaked, detected, scannerFailed)...)
	if !expectationsMet(captures, expectations) {
		reasons = append(reasons, "a content expectation was not met")
	}

	r.mu.Lock()
	if len(reasons) > 0 {
		r.failed = true
	}
	valid := !r.failed
	if !valid && len(reasons) == 0 {
		reasons = append(reasons, "observation incomplete: output or registration changed during Check")
	}
	r.reported = !valid
	r.mu.Unlock()
	for _, reason := range reasons {
		r.tb.Error("embargotest: " + reason)
	}
	return valid
}

func validate(f func([]byte) bool, data []byte) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	return f(data)
}

func expectationsMet(captures map[string][]byte, expectations []expectation) bool {
	for _, e := range expectations {
		data, exists := captures[e.name]
		if !exists || !validate(e.validate, append([]byte(nil), data...)) {
			return false
		}
	}
	return true
}
