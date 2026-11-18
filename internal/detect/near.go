package detect

// nearRule is the shared skeleton of keyword-near detectors (ACH trace, CVV,
// bank account, merchant and terminal IDs): a candidate is a run of class bytes,
// minLen to maxLen long, within radius bytes of a keyword end, and accept
// decides whether it is reported and with which confidence.
type nearRule struct {
	keywords *keywordSet
	class    func(byte) bool
	accept   func(data []byte, seq digitSequence) (confidence float64, ok bool)
	radius   int
	minLen   int
	maxLen   int
	// overlap skips a candidate overlapping any finding already in dst; the
	// default skips a candidate whose start was already reported.
	overlap bool
}

// fixedConfidence accepts every candidate with one score.
func fixedConfidence(score float64) func([]byte, digitSequence) (float64, bool) {
	return func([]byte, digitSequence) (float64, bool) { return score, true }
}

// scan appends name's findings in data to dst. posMap maps a normalized data
// offset to the original input, and nil means data is the original input.
func (r *nearRule) scan(dst []Finding, name DetectorName, data []byte, posMap []int) []Finding {
	matches := r.keywords.findPositions(data)
	if len(matches) == 0 {
		return dst
	}
	var used map[int]struct{}
	if !r.overlap {
		used = make(map[int]struct{})
	}
	for _, m := range matches {
		for _, seq := range extractNear(data, m.end, r.radius, r.minLen, r.maxLen, r.class) {
			if r.reported(dst, used, seq) {
				continue
			}
			confidence, ok := r.accept(data, seq)
			if !ok {
				continue
			}
			if used != nil {
				used[seq.start] = struct{}{}
			}
			dst = append(dst, viewFinding(name, posMap, seq.start, seq.end, confidence))
		}
	}
	return dst
}

// reported applies the rule's deduplication mode to one candidate.
func (r *nearRule) reported(dst []Finding, used map[int]struct{}, seq digitSequence) bool {
	if r.overlap {
		return overlapsFinding(dst, seq.start, seq.end)
	}
	_, ok := used[seq.start]
	return ok
}

// overlapsFinding reports whether [start, end) overlaps any existing finding.
// A digit run inside an already reported merchant ID (e.g., "00000000" in
// "A00000000A00000") must not be reported again as a terminal ID.
func overlapsFinding(findings []Finding, start, end int) bool {
	for _, f := range findings {
		if start < f.End && end > f.Start {
			return true
		}
	}
	return false
}
