package embargotest

import (
	"maps"
	"slices"
	"strings"

	"github.com/nao1215/embargo"
)

type (
	scannerOption struct{ scanner *embargo.Scanner }
	kindsOption   []embargo.Kind
	valuesOption  []string
)

// WithScanner replaces the default 26 built-ins at minimum confidence 0.
// National ID kinds and entropy are opt-in; NewScanner(WithAll()) selects all 38.
// Nil fails the test.
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
	findings, failed := r.scanFindings(data)
	for _, f := range findings {
		r.metadataKinds[f.Kind] = true
	}
	r.detected = r.detected || len(findings) > 0
	r.scannerFailed = r.scannerFailed || failed
}

// contentReasons names the sinks where the canary or a finding appeared and
// the finding kinds, never the captured bytes. Transient HTTP header values
// and interim responses are reported as "observed HTTP headers".
func (r *Recorder) contentReasons(captures map[string][]byte, interim [][]byte, leaked, detected, scannerFailed bool) []string {
	var leakedIn []string
	foundIn := map[string]map[embargo.Kind]bool{}
	if detected {
		foundIn[httpHeadersSink] = maps.Clone(r.metadataKinds)
	}
	if leaked {
		leakedIn = append(leakedIn, httpHeadersSink)
	}
	observe := func(name string, capture []byte) {
		if containsCanary(capture, r.needles) {
			leakedIn = append(leakedIn, name)
		}
		findings, failed := r.scanFindings(capture)
		scannerFailed = scannerFailed || failed
		for _, f := range findings {
			if foundIn[name] == nil {
				foundIn[name] = map[embargo.Kind]bool{}
			}
			foundIn[name][f.Kind] = true
		}
	}
	for _, capture := range interim {
		observe(httpHeadersSink, capture)
	}
	for _, name := range slices.Sorted(maps.Keys(captures)) {
		observe(r.printableSinkName(name), captures[name])
	}
	var reasons []string
	if len(leakedIn) > 0 {
		slices.Sort(leakedIn)
		reasons = append(reasons, "the fake secret appeared in captured output: "+strings.Join(slices.Compact(leakedIn), ", "))
	}
	if len(foundIn) > 0 {
		var parts []string
		for _, name := range slices.Sorted(maps.Keys(foundIn)) {
			kinds := make([]string, 0, len(foundIn[name]))
			for kind := range foundIn[name] {
				kinds = append(kinds, r.printableKind(kind))
			}
			slices.Sort(kinds)
			parts = append(parts, name+" ("+strings.Join(slices.Compact(kinds), ", ")+")")
		}
		reasons = append(reasons, "sensitive data appeared in captured output: "+strings.Join(parts, "; "))
	}
	if scannerFailed {
		reasons = append(reasons, "scanner failed")
	}
	return reasons
}

// httpHeadersSink names transient header values and interim responses.
const httpHeadersSink = "observed HTTP headers"

// printableSinkName returns a sink name for a failure message. Names come
// from test code, but one built from data could carry the value under test,
// so a name that is long, uses bytes outside letters, digits and _ . / : -,
// contains the canary or has a finding of its own is replaced.
func (r *Recorder) printableSinkName(name string) string {
	if printableLabel(name) && !containsCanary([]byte(name), r.needles) {
		if findings, failed := r.scanFindings([]byte(name)); len(findings) == 0 && !failed {
			return name
		}
	}
	return "a sink with an unprintable name"
}

// printableKind applies the same rule to a custom detector's kind.
func (r *Recorder) printableKind(kind embargo.Kind) string {
	if printableLabel(string(kind)) && !containsCanary([]byte(kind), r.needles) {
		return string(kind)
	}
	return "custom kind"
}

func printableLabel(name string) bool {
	const maxLabel = 64
	if name == "" || len(name) > maxLabel {
		return false
	}
	for i := range len(name) {
		c := name[i]
		alphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !alphaNum && !strings.ContainsRune("_./:-", rune(c)) {
			return false
		}
	}
	return true
}
