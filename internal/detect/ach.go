package detect

// ACHTraceDetail holds ACH trace number-specific detail information.
type ACHTraceDetail struct {
	// ODFIRoutingNumber is the first 8 digits of the trace number,
	// representing the Originating Depository Financial Institution's
	// routing number (without the check digit).
	ODFIRoutingNumber string
}

// ACHTrace implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindACHTrace.
type ACHTrace struct {
	achKeywords *keywordSet
}

// NewACHTrace uses ACH context and routing prefixes to find transaction trace numbers.
func NewACHTrace() *ACHTrace {
	return &ACHTrace{achKeywords: achKeywords()}
}

// Name returns "ach_trace".
func (d *ACHTrace) Name() DetectorName {
	return NameACHTrace
}

// Hints returns the pre-filter substrings for [ACHTrace].
func (d *ACHTrace) Hints() [][]byte {
	return [][]byte{
		[]byte("ach"),   // covers ACH, Ach, ach
		[]byte("trace"), // covers Trace, TRACE, trace
	}
}

// Scan returns matches in data using the rules documented on [ACHTrace].
func (d *ACHTrace) Scan(data []byte) []Finding {
	matches := d.achKeywords.findPositions(data)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding
	used := make(map[int]struct{})

	for _, m := range matches {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		seqs := extractDigitsNear(data, m.end, 50, 15, 15)
		for _, seq := range seqs {
			if _, ok := used[seq.start]; ok {
				continue
			}

			// Ensure the digit sequence doesn't overlap with the keyword.
			if seq.start < m.end && seq.end > m.start {
				continue
			}

			digits := data[seq.start:seq.end]

			// Validate that the first 2 digits are a valid Federal Reserve
			// routing symbol range.
			if abaFederalReserveDistrict(digits[:9]) == "" {
				continue
			}

			used[seq.start] = struct{}{}

			odfiRouting := string(digits[:8])

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        seq.start,
				End:          seq.end,
				//nolint:mnd // The detector contract documents this heuristic score.
				Confidence: 0.75,
				RawValue:   string(data[seq.start:seq.end]),
				Detail:     &ACHTraceDetail{ODFIRoutingNumber: odfiRouting},
			})
		}
	}

	return findings
}

// achKeywords are the context keywords for ACH trace number detection.
// Bare "trace" / "Trace" / "TRACE" are intentionally excluded because the
// word "trace" appears frequently in non-financial contexts (e.g., stack
// traces, distributed-tracing IDs), causing false positives with nearby
// 15-digit numbers. Only compound phrases ("trace number", "ACH trace")
// or the acronym "ACH" itself are used.
//
// Common mixed-case variants (e.g., "Trace number") are included to
// reduce false negatives from case variations in real-world documents.
func achKeywords() *keywordSet {
	return newKeywordSet([][]byte{
		[]byte("ACH"),
		[]byte("ach"),
		[]byte("Ach"),
		[]byte("ACH Trace"),
		[]byte("ACH trace"),
		[]byte("ACH TRACE"),
		[]byte("ach trace"),
		[]byte("Ach Trace"),
		[]byte("Ach trace"),
		[]byte("trace number"),
		[]byte("Trace Number"),
		[]byte("Trace number"),
		[]byte("TRACE NUMBER"),
		[]byte("trace no"),
		[]byte("Trace No"),
		[]byte("Trace no"),
		[]byte("TRACE NO"),
		[]byte("trace #"),
		[]byte("Trace #"),
		[]byte("TRACE #"),
		[]byte("trace#"),
		[]byte("Trace#"),
		[]byte("TRACE#"),
	})
}
