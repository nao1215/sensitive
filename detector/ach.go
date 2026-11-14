package detector

// ACHTraceDetail holds ACH trace number-specific detail information.
type ACHTraceDetail struct {
	// ODFIRoutingNumber is the first 8 digits of the trace number,
	// representing the Originating Depository Financial Institution's
	// routing number (without the check digit).
	ODFIRoutingNumber string
}

// ACHTrace detects 15-digit ACH transaction trace identifiers from context; the first eight digits identify the originating financial institution and the last seven are its sequence number.
//
//  1. Find ACH or trace number (ASCII case-insensitive).
//  2. Search within 50 bytes of the keyword end for a separate 15-digit sequence.
//  3. Require the first two digits to fall in an ABA routing prefix range, without applying a checksum; score the match as 0.75.
type ACHTrace struct{}

// NewACHTrace creates a new ACH trace number detector.
func NewACHTrace() *ACHTrace {
	return &ACHTrace{}
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
	matches := achKeywords.findPositions(data)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding
	used := make(map[int]struct{})

	for _, m := range matches {
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
				Confidence:   0.75,
				RawValue:     string(data[seq.start:seq.end]),
				Detail:       &ACHTraceDetail{ODFIRoutingNumber: odfiRouting},
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
var achKeywords = newKeywordSet([][]byte{
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
