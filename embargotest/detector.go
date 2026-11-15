package embargotest

import "github.com/nao1215/embargo"

type (
	scannerOption struct{ scanner *embargo.Scanner }
	kindsOption   []embargo.Kind
	valuesOption  []string
)

// WithScanner uses scanner instead of the default all-built-in policy. Nil fails the test.
func WithScanner(scanner *embargo.Scanner) Option { return scannerOption{scanner: scanner} }

func (o scannerOption) apply(r *Recorder) bool {
	if o.scanner == nil {
		return false
	}
	r.scanner = o.scanner
	return true
}

// WithAllowedKinds allows fixture findings of these nonempty kinds, including custom kinds.
// Allowances accumulate; canary checks are never disabled. The slice is copied.
func WithAllowedKinds(kinds ...embargo.Kind) Option { return append(kindsOption(nil), kinds...) }

func (o kindsOption) apply(r *Recorder) bool {
	for _, kind := range o {
		if kind == "" {
			return false
		}
		r.allowedKinds[kind] = true
	}
	return true
}

// WithAllowedValues allows exact nonempty values in original captured bytes, across kinds.
// Matching is case-sensitive, without decoding or normalization. The slice is copied.
// Allowances accumulate and do not bypass canary checks.
func WithAllowedValues(values ...string) Option { return append(valuesOption(nil), values...) }

func (o valuesOption) apply(r *Recorder) bool {
	for _, value := range o {
		if value == "" {
			return false
		}
		r.allowedValues[value] = true
	}
	return true
}

func (r *Recorder) scan(data []byte) (found, failed bool) {
	findings, failed := r.scanFindings(data)
	return len(findings) > 0, failed
}

func (r *Recorder) scanFindings(data []byte) (findings []embargo.Finding, failed bool) {
	failed = true
	defer func() {
		if failed {
			_ = recover() //nolint:errcheck // Discard panic values, including panic(nil) compatibility mode.
		}
	}()
	all := r.scanner.Scan(data)
	findings = all[:0]
	for _, f := range all {
		if !r.allowedKinds[f.Kind] && !r.allowedValues[string(data[f.Start:f.End])] {
			findings = append(findings, f)
		}
	}
	return findings, false
}

// observeMetadata checks transient HTTP data while the recorder lock is held.
func (r *Recorder) observeMetadata(data []byte) {
	if containsCanary(data, r.needles) {
		r.leaked = true
	}
	found, failed := r.scan(data)
	r.detected = r.detected || found
	r.scannerFailed = r.scannerFailed || failed
}

func (r *Recorder) contentReasons(captures map[string][]byte, interim [][]byte, leaked, detected, scannerFailed bool) []string {
	data := make([][]byte, 0, len(captures)+len(interim))
	data = append(data, interim...)
	for _, capture := range captures {
		data = append(data, capture)
	}
	for _, capture := range data {
		leaked = containsCanary(capture, r.needles) || leaked
		found, failed := r.scan(capture)
		detected = detected || found
		scannerFailed = scannerFailed || failed
	}
	var reasons []string
	if leaked {
		reasons = append(reasons, "the fake secret appeared in captured output")
	}
	if detected {
		reasons = append(reasons, "sensitive data appeared in captured output")
	}
	if scannerFailed {
		reasons = append(reasons, "scanner failed")
	}
	return reasons
}
