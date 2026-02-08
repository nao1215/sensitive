package detector

// ACHTraceDetail holds ACH trace number-specific detail information.
type ACHTraceDetail struct {
	// ODFIRoutingNumber is the first 8 digits of the trace number,
	// representing the Originating Depository Financial Institution's
	// routing number (without the check digit).
	ODFIRoutingNumber string
}

// ACHTrace detects ACH (Automated Clearing House) trace numbers in text.
//
// An ACH trace number is a 15-digit identifier used to track ACH transactions.
// The first 8 digits are the ODFI (Originating Depository Financial Institution)
// routing number, and the remaining 7 digits are a sequence number assigned by
// the originator.
//
// Because bare 15-digit numbers are common (phone numbers, IDs, etc.), this
// detector requires a context keyword to be present nearby.
//
// Detection logic:
//  1. Scan for context keywords: "ACH", "ach", "trace number", "Trace Number"
//  2. Within a 50-byte radius of each keyword, look for a 15-digit number
//  3. Validate the first 8 digits by prepending a check digit (making a 9-digit
//     ABA routing number) would be unreliable, so instead we validate that
//     the first 2 digits fall within a valid Federal Reserve routing symbol range
//
// Confidence: 0.75 when a context keyword and valid 15-digit sequence are found.
type ACHTrace struct{}

// NewACHTrace creates a new ACH trace number detector.
func NewACHTrace() *ACHTrace {
	return &ACHTrace{}
}

// Name returns "ach_trace".
func (d *ACHTrace) Name() DetectorName {
	return NameACHTrace
}

// Hints returns byte sequences for pre-filtering.
// ACH trace detection requires context keywords to avoid false positives.
// "trace" is included as a hint (not a keyword) because compound keywords
// like "trace number" contain it, and the hint filter uses bytes.Contains.
//
// ASCII hints are matched case-insensitively by Scanner's hint filter, so a
// single lowercase entry covers all case variants.
func (d *ACHTrace) Hints() [][]byte {
	return [][]byte{
		[]byte("ach"),   // covers ACH, Ach, ach
		[]byte("trace"), // covers Trace, TRACE, trace
	}
}

// Scan examines data for ACH trace numbers near context keywords and returns findings.
func (d *ACHTrace) Scan(data []byte) []Finding {
	matches := findKeywordPositions(data, achKeywords)
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
var achKeywords = [][]byte{
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
}
