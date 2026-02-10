package detector

import "regexp"

// Regex is a user-defined regular expression detector for custom patterns.
// It serves as a fallback mechanism for patterns that do not warrant a
// dedicated detector implementation.
//
// Example usage:
//
//	d := detector.NewRegex(
//	    "internal_id",
//	    regexp.MustCompile(`PROJ-\d{6}`),
//	    [][]byte{[]byte("PROJ-")},
//	    0.8,
//	)
type Regex struct {
	name       DetectorName
	pattern    *regexp.Regexp
	hints      [][]byte
	confidence float64
}

// NewRegex creates a new Regex detector with the given name, compiled pattern,
// hint byte sequences, and fixed confidence value.
//
// The pattern must be pre-compiled using regexp.MustCompile or regexp.Compile
// and must not be nil. Passing a nil pattern causes a panic because Scan would
// otherwise dereference it at runtime.
//
// The confidence value is clamped to the [0, 1] range. Values below 0 are
// treated as 0 and values above 1 are treated as 1.
//
// Hints should contain byte sequences that are guaranteed to be present in any
// match, enabling the Scanner's pre-filter to skip non-matching input efficiently.
// An empty hints slice causes Scan to be called unconditionally (discouraged).
func NewRegex(name DetectorName, pattern *regexp.Regexp, hints [][]byte, confidence float64) *Regex {
	if pattern == nil {
		panic("detector.NewRegex: pattern must not be nil")
	}
	return &Regex{
		name:       name,
		pattern:    pattern,
		hints:      hints,
		confidence: clampConfidence(confidence),
	}
}

// clampConfidence restricts v to the [0, 1] range.
func clampConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// Name returns the detector name specified at construction time.
func (d *Regex) Name() DetectorName {
	return d.name
}

// Hints returns the hint byte sequences specified at construction time.
func (d *Regex) Hints() [][]byte {
	return d.hints
}

// Scan examines data using the compiled regular expression and returns
// findings for all non-overlapping matches.
func (d *Regex) Scan(data []byte) []Finding {
	matches := d.pattern.FindAllIndex(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]Finding, 0, len(matches))
	for _, m := range matches {
		findings = append(findings, Finding{
			DetectorName: d.name,
			Start:        m[0],
			End:          m[1],
			Confidence:   d.confidence,
			RawValue:     string(data[m[0]:m[1]]),
		})
	}
	return findings
}
