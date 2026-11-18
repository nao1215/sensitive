package detect

import "github.com/nao1215/embargo/internal/ascii"

// ACHTrace implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindACHTrace.
type ACHTrace struct {
	rule nearRule
}

// NewACHTrace uses ACH context and routing prefixes to find transaction trace numbers.
func NewACHTrace() *ACHTrace {
	//nolint:mnd // Literal field widths follow the format rules documented on this detector.
	return &ACHTrace{rule: nearRule{keywords: achKeywords(), class: ascii.IsDigit, accept: achPrefix, radius: 50, minLen: 15, maxLen: 15}}
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
	return d.rule.scan(nil, d.Name(), data, nil)
}

// achPrefix accepts a trace number whose first two digits are a valid Federal
// Reserve routing symbol range.
func achPrefix(data []byte, seq digitSequence) (float64, bool) {
	//nolint:mnd // The routing prefix is the first nine digits; the score is documented on this detector.
	return 0.75, validABAPrefix(data[seq.start : seq.start+9])
}

// achKeywords are the context keywords for ACH trace number detection.
// Bare "trace" / "Trace" / "TRACE" are intentionally excluded because the
// word "trace" appears frequently in non-financial contexts (e.g., stack
// traces, distributed-tracing IDs), causing false positives with nearby
// 15-digit numbers. Only compound phrases ("trace number", "ACH trace")
// or the acronym "ACH" itself are used.
// keywordSet folds ASCII case, so each keyword is listed once.
func achKeywords() *keywordSet {
	return newKeywordSet([][]byte{
		[]byte("ACH"),
		[]byte("ACH Trace"),
		[]byte("trace number"),
		[]byte("trace no"),
		[]byte("trace #"),
		[]byte("trace#"),
	})
}
