package sensitive

import (
	"bytes"
	"sort"

	"github.com/nao1215/sensitive/internal/ascii"
)

// Scanner detects sensitive data with configured [Detector] implementations. Create one with [NewScanner]; concurrent scans require each registered detector to support concurrent use.
type Scanner struct {
	detectors      []Detector
	hintCache      [][]hintEntry // pre-computed per detector
	sortByPosition bool
	skipDedup      bool
	minConfidence  float64
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

// NewScanner applies opts in order; no options enables no detectors. Nil options are ignored, and the last registration for each detector name wins.
func NewScanner(opts ...Option) *Scanner {
	s := &Scanner{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(s)
	}
	s.detectors = deduplicateDetectors(s.detectors)
	s.hintCache = buildHintCache(s.detectors)
	return s
}

// buildHintCache pre-computes lowered hints for each detector so that
// ascii.LowerCopy(hint) is not called on every Scan invocation.
func buildHintCache(detectors []Detector) [][]hintEntry {
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

// deduplicateDetectors removes duplicate detectors from the slice, keeping
// the last occurrence of each detector name. This ensures that when WithAll()
// and individual With*() options are combined, each detector runs only once.
func deduplicateDetectors(detectors []Detector) []Detector {
	if len(detectors) <= 1 {
		return detectors
	}

	seen := make(map[DetectorName]struct{}, len(detectors))
	// Walk backwards so the last registration wins.
	result := make([]Detector, 0, len(detectors))
	for i := len(detectors) - 1; i >= 0; i-- {
		name := detectors[i].Name()
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, detectors[i])
	}

	// Reverse to restore original order.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// Scan returns findings in data, or nil for empty input. It keeps the highest-confidence non-overlapping findings, then orders them by confidence descending, start offset ascending, and detector name.
//
// Overlap ties prefer an earlier start, then a later end, then detector name. [WithoutDedup] retains overlaps; [WithSortByPosition] changes ordering; [WithMinConfidence] filters the final results.
func (s *Scanner) Scan(data []byte) []Finding {
	// Stage 0: Empty data check.
	if len(data) == 0 {
		return nil
	}

	var allFindings []Finding
	var foldedData []byte
	var foldedReady bool

	// Stage 1 & 2: Hint-based pre-filter + Detector.Scan.
	for i, d := range s.detectors {
		if !matchesAnyHint(s.hintCache[i], data, &foldedData, &foldedReady) {
			continue
		}
		allFindings = append(allFindings, d.Scan(data)...)
	}

	// Stage 3: Deduplicate overlapping findings (unless disabled) and sort.
	if !s.skipDedup {
		allFindings = dedup(allFindings)
	}
	sortFindings(allFindings, s.sortByPosition)

	// Stage 4: Filter by minimum confidence threshold (if configured).
	if s.minConfidence > 0 {
		filtered := allFindings[:0]
		for _, f := range allFindings {
			if f.Confidence >= s.minConfidence {
				filtered = append(filtered, f)
			}
		}
		allFindings = filtered
	}
	return allFindings
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
		} else {
			if bytes.Contains(data, e.lowered) {
				return true
			}
		}
	}
	return false
}

// sortFindings sorts findings by confidence (descending) or position
// (ascending), with tiebreakers for full determinism.
func sortFindings(findings []Finding, byPosition bool) {
	if byPosition {
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Start != findings[j].Start {
				return findings[i].Start < findings[j].Start
			}
			if findings[i].Confidence != findings[j].Confidence {
				return findings[i].Confidence > findings[j].Confidence
			}
			return findings[i].DetectorName < findings[j].DetectorName
		})
	} else {
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Confidence != findings[j].Confidence {
				return findings[i].Confidence > findings[j].Confidence
			}
			if findings[i].Start != findings[j].Start {
				return findings[i].Start < findings[j].Start
			}
			return findings[i].DetectorName < findings[j].DetectorName
		})
	}
}

// ScanString calls [Scanner.Scan] on the bytes of text.
func (s *Scanner) ScanString(text string) []Finding {
	return s.Scan([]byte(text))
}

// dedup removes overlapping findings, keeping the one with the highest
// confidence when two findings overlap in byte position.
//
// The algorithm sorts findings by confidence (descending) and greedily
// accepts each finding only if it does not overlap with any already
// accepted finding. This correctly handles "bridging" overlaps: if
// A(0-10) and C(11-20) do not overlap directly, both are kept even
// when an intermediate B(9-12) overlaps with both.
//
// Accepted findings are maintained sorted by Start position so that
// overlap checks use binary search (O(log n)) instead of a linear
// scan. The sorted-order insertion via copy is O(k) per insert, so
// worst-case total complexity is O(n^2). In practice k (the number
// of accepted, non-overlapping findings) is small, keeping the
// insert cost negligible.
func dedup(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}

	// Sort by confidence descending so the highest-confidence findings
	// are considered first. Tiebreakers (Start, End, DetectorName) ensure
	// deterministic dedup results regardless of the input order.
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Confidence != findings[j].Confidence {
			return findings[i].Confidence > findings[j].Confidence
		}
		if findings[i].Start != findings[j].Start {
			return findings[i].Start < findings[j].Start
		}
		if findings[i].End != findings[j].End {
			return findings[i].End > findings[j].End
		}
		return findings[i].DetectorName < findings[j].DetectorName
	})

	// result is kept sorted by Start to allow binary search for overlaps.
	result := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if dedupOverlaps(result, f) {
			continue
		}
		// Insert f into result at the correct position to maintain
		// ascending Start order.
		idx := sort.Search(len(result), func(i int) bool {
			return result[i].Start >= f.Start
		})
		result = append(result, Finding{})
		copy(result[idx+1:], result[idx:])
		result[idx] = f
	}
	return result
}

// dedupOverlaps reports whether f overlaps with any finding in the
// sorted (by Start) accepted slice. Because accepted intervals are
// non-overlapping and sorted, only the neighbors around the binary
// search insertion point need to be checked — O(log n) per call.
func dedupOverlaps(accepted []Finding, f Finding) bool {
	if len(accepted) == 0 {
		return false
	}
	// Find first accepted finding with Start >= f.Start.
	idx := sort.Search(len(accepted), func(i int) bool {
		return accepted[i].Start >= f.Start
	})
	// Check the finding at idx (starts at or after f.Start).
	if idx < len(accepted) && accepted[idx].Start < f.End {
		return true
	}
	// Check the finding just before idx (starts before f.Start).
	if idx > 0 && accepted[idx-1].End > f.Start {
		return true
	}
	return false
}
