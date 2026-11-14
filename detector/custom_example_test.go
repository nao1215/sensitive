package detector_test

import (
	"bytes"
	"fmt"

	"github.com/nao1215/sensitive"
	"github.com/nao1215/sensitive/detector"
)

// markerDetector finds an application's exact internal classification marker.
type markerDetector struct {
	marker []byte
}

// Name returns the name used for scanner registration and findings.
func (d markerDetector) Name() detector.DetectorName { return "internal_marker" }

// Hints returns a substring present in every match.
func (d markerDetector) Hints() [][]byte { return [][]byte{d.marker} }

// Scan returns non-overlapping marker occurrences with original byte offsets.
func (d markerDetector) Scan(data []byte) []detector.Finding {
	if len(d.marker) == 0 {
		return nil
	}
	var findings []detector.Finding
	for start := 0; start < len(data); {
		n := bytes.Index(data[start:], d.marker)
		if n < 0 {
			break
		}
		start += n
		end := start + len(d.marker)
		findings = append(findings, detector.Finding{
			DetectorName: d.Name(), Start: start, End: end,
			RawValue: string(data[start:end]), Confidence: 1,
		})
		start = end
	}
	return findings
}

func ExampleDetector() {
	custom := markerDetector{marker: []byte("INTERNAL-ONLY")}
	scanner := sensitive.NewScanner(sensitive.WithDetector(custom))
	for _, f := range scanner.ScanString("scope: INTERNAL-ONLY") {
		fmt.Printf("%s [%d:%d]: %s\n", f.DetectorName, f.Start, f.End, f.RawValue)
	}
	// Output:
	// internal_marker [7:20]: INTERNAL-ONLY
}
