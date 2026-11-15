package embargo

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/nao1215/embargo/internal/ascii"
	"github.com/nao1215/embargo/internal/detect"
)

// Scanner holds immutable scan policy. Its zero value selects all built-in detectors.
// Concurrent use requires custom detectors to support concurrent Scan calls.
type Scanner struct {
	kinds         map[Kind]bool
	detectors     []detect.Detector
	hintCache     [][]hintEntry
	custom        []Detector
	hintIndex     [256][]dispatchHint
	minConfidence float64
	unconditional uint32
	initialized   bool
}

// hintEntry caches a detector's hint in pre-lowered form to avoid
// per-scan allocations in the hint matching hot path.
type hintEntry struct {
	// lowered is the pre-lowered hint (same as original if no ASCII letters).
	lowered []byte
	// needFold is true if the hint contained ASCII letters, requiring
	// case-folded data for matching.
	needFold bool
}

// NewScanner selects all built-ins by default, including IP addresses and context-based
// detectors. The default minimum confidence is 0, including ambiguous candidates.
// Use WithKinds to narrow selection. Options apply in order; nil options are ignored.
func NewScanner(opts ...ScannerOption) *Scanner {
	s := &Scanner{initialized: true}
	for _, opt := range opts {
		if opt != nil {
			opt.apply(s)
		}
	}
	for _, d := range builtins() {
		if s.kinds == nil || s.kinds[Kind(d.Name())] {
			s.detectors = append(s.detectors, d)
		}
	}
	s.hintCache = buildHintCache(s.detectors)
	s.buildDispatch()
	return s
}

// buildHintCache pre-computes lowered hints for each detector so that
// ascii.LowerCopy(hint) is not called on every Scan invocation.
func buildHintCache(detectors []detect.Detector) [][]hintEntry {
	cache := make([][]hintEntry, len(detectors))
	for i, d := range detectors {
		hints := d.Hints()
		if len(hints) == 0 {
			continue
		}
		entries := make([]hintEntry, len(hints))
		for j, h := range hints {
			if ascii.HasLetter(h) {
				entries[j] = hintEntry{lowered: ascii.LowerCopy(h), needFold: true}
			} else {
				entries[j] = hintEntry{lowered: h, needFold: false}
			}
		}
		cache[i] = entries
	}
	return cache
}

// Scan returns every finding, including overlaps, ordered by start, descending end,
// kind, then descending confidence. Built-ins decode one layer of valid percent
// escapes (%HH), preserving literal + and invalid escapes; offsets always refer
// to original bytes. Other encodings are not decoded. Custom detectors receive
// the original bytes. Invalid custom findings panic with a fixed message.
func (s *Scanner) Scan(data []byte) []Finding {
	if len(data) == 0 {
		return nil
	}
	if !s.initialized {
		return NewScanner().Scan(data)
	}
	scanData, positions := decodePercent(data)
	var findings []Finding
	selected := s.selectDetectors(scanData)
	for i, d := range s.detectors {
		if selected&(1<<i) == 0 {
			continue
		}
		for _, f := range d.Scan(scanData) {
			if positions != nil {
				f.Start, f.End = positions[f.Start], positions[f.End]
			}
			findings = append(findings, Finding{Kind: Kind(f.DetectorName), Start: f.Start, End: f.End, Confidence: f.Confidence})
		}
	}
	for _, d := range s.custom {
		findings = append(findings, d.Scan(data)...)
	}
	result := findings[:0]
	for _, f := range findings {
		if f.Kind == "" || f.Start < 0 || f.End <= f.Start || f.End > len(data) || !validScore(f.Confidence) {
			panic("embargo: invalid detector finding")
		}
		if f.Confidence >= s.minConfidence {
			result = append(result, f)
		}
	}
	slices.SortStableFunc(result, compareFindings)
	return result
}

// ScanString scans the bytes of text.
func (s *Scanner) ScanString(text string) []Finding { return s.Scan([]byte(text)) }

func compareFindings(a, b Finding) int {
	if n := cmp.Compare(a.Start, b.Start); n != 0 {
		return n
	}
	if n := cmp.Compare(b.End, a.End); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Kind, b.Kind); n != 0 {
		return n
	}
	return cmp.Compare(b.Confidence, a.Confidence)
}

// matchesAnyHint reports whether data matches any hint in entries.
// If a hint requires case-folded matching, foldedData is lazily populated.
func matchesAnyHint(entries []hintEntry, data []byte, foldedData *[]byte, foldedReady *bool) bool {
	if len(entries) == 0 {
		return true
	}
	for _, e := range entries {
		if e.needFold {
			if !*foldedReady {
				*foldedData = ascii.LowerCopy(data)
				*foldedReady = true
			}
			if bytes.Contains(*foldedData, e.lowered) {
				return true
			}
		} else if bytes.Contains(data, e.lowered) {
			return true
		}
	}
	return false
}
