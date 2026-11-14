package detector

import "regexp"

// Regex detects custom patterns with a compiled regular expression.
//
//  1. Find every non-overlapping match, including empty matches allowed by the pattern.
//  2. Return each original byte range with the configured name and fixed confidence.
type Regex struct {
	name       DetectorName
	pattern    *regexp.Regexp
	hints      [][]byte
	confidence float64
}

// NewRegex creates a detector with pattern and a fixed confidence clamped to [0, 1]. It panics if pattern is nil; hints follow [Detector.Hints] and must not change after registration.
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
