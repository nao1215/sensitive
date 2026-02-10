package sensitive

import (
	"bytes"
	"sort"

	"github.com/nao1215/sensitive/internal/ascii"
)

// Scanner scans text for sensitive data using registered Detectors.
// It implements a multi-stage filtering pipeline:
//
//  1. Empty data check: Immediately returns if the input is empty.
//  2. Hint-based pre-filter: Uses bytes.Contains with each Detector's
//     hints to quickly skip detectors that cannot match the input.
//     ASCII letters in hints are matched case-insensitively.
//     Hints must be exhaustive for the detector's domain (i.e., every
//     possible match must contain at least one hint byte sequence), or
//     empty/nil to always run the detector. Non-exhaustive hints will
//     cause silent detection misses.
//  3. Detector.Scan: Runs only the detectors whose hints matched.
//  4. Result merging: By default, deduplicates overlapping findings
//     (keeping the highest confidence) and sorts by confidence
//     (descending). Use [WithSortByPosition] to sort by byte offset
//     instead, or [WithoutDedup] to keep all findings including
//     overlapping ones.
//
// Create a Scanner using [NewScanner] with the desired options.
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

// NewScanner creates a new Scanner with the given options.
// Each option enables a specific detector or adds a custom one.
// If the same detector is registered more than once (e.g., by combining
// [WithAll] with an individual option like [WithPAN]), the duplicate is
// silently removed so that each detector runs at most once.
//
//	// Enable all built-in detectors
//	scanner := sensitive.NewScanner(sensitive.WithAll())
//
//	// Enable only PAN and email detection
//	scanner := sensitive.NewScanner(sensitive.WithPAN(), sensitive.WithEmail())
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

// Scan examines the given byte slice for sensitive data and returns all findings.
// The multi-stage filtering pipeline ensures that detectors are only invoked
// when their hint sequences are found in the data, minimizing scan cost.
//
// By default the returned findings are deduplicated (overlapping findings
// are merged, keeping the highest confidence) and sorted by confidence in
// descending order. Findings with the same confidence are ordered by byte
// offset (ascending), then by detector name for full determinism.
// Use [WithSortByPosition] to sort by byte offset (ascending) instead.
// Use [WithoutDedup] to receive all findings including overlapping ones
// from different detectors.
//
// If [WithMinConfidence] is configured, the confidence threshold is applied
// after deduplication and sorting. This means deduplication always sees the
// full set of findings, so the highest-confidence finding for each byte range
// is kept regardless of the threshold. The threshold then removes only the
// remaining low-confidence findings from the final output.
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

// ScanString is a convenience method that scans a string for sensitive data.
// It converts the string to a byte slice and calls [Scanner.Scan].
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
