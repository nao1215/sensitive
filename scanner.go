package embargo

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/nao1215/embargo/internal/ascii"
	"github.com/nao1215/embargo/internal/detect"
)

// Scanner holds immutable scan policy. Its zero value uses the same selection as NewScanner.
// Concurrent use requires custom detectors to support concurrent Scan calls.
type Scanner struct {
	sensitiveKeys map[string]struct{}
	kinds         map[Kind]bool
	detectors     []detect.Detector
	hintCache     [][]hintEntry
	custom        []Detector
	hintIndex     [256][]dispatchHint
	minConfidence float64
	unconditional uint64
	initialized   bool
	allKinds      bool
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

// NewScanner starts with 25 built-ins; the additional country families and KindHighEntropy are opt-in.
// WithAll enables all 37 families; WithKinds selects the regions and formats an application handles.
// Minimum confidence defaults to 0, so ambiguous numeric and contextual candidates remain.
// Select WithKinds when the application knows which data it handles; fewer detectors reduce work and unrelated findings.
// See https://github.com/nao1215/embargo/blob/main/doc/benchmarks.md for measured kind sets.
// Options apply in order; nil options are ignored.
func NewScanner(opts ...ScannerOption) *Scanner {
	s := &Scanner{initialized: true}
	for _, opt := range opts {
		if opt != nil {
			opt.apply(s)
		}
	}
	for _, d := range builtins() {
		if (s.kinds == nil && (s.allKinds || defaultKind(Kind(d.Name())))) || s.kinds[Kind(d.Name())] {
			if credential, ok := d.(*detect.Credential); ok && s.sensitiveKeys != nil {
				credential.MatchKey = s.sensitiveKey
			}
			s.detectors = append(s.detectors, d)
		}
	}
	s.hintCache = buildHintCache(s.detectors)
	if len(s.detectors) > 1 {
		s.buildDispatch()
	}
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
// escapes (%HH), except KindCredential parses original URL/DSN delimiters.
// Literal + and invalid escapes are preserved; offsets always refer
// to original bytes. Other encodings are not decoded. Custom detectors receive
// the original bytes. Invalid custom findings panic with a fixed message.
func (s *Scanner) Scan(data []byte) []Finding {
	return s.scan(data, nil)
}

func (s *Scanner) scan(data []byte, canceled func() error) []Finding {
	if scanCanceled(canceled) || len(data) == 0 {
		return nil
	}
	if !s.initialized {
		return NewScanner().scan(data, canceled)
	}
	scanData := data
	var positions []int
	var selected uint64
	if len(s.detectors) > 0 {
		scanData, positions = normalizedScanInput(data)
		selected = s.selectDetectors(scanData)
	}
	var findings []Finding
	for i, d := range s.detectors {
		if scanCanceled(canceled) {
			return nil
		}
		if selected&(1<<i) == 0 {
			continue
		}
		input := scanData
		raw := d.Name() == "credential"
		if raw {
			input = data
		}
		for _, f := range d.Scan(input) {
			if positions != nil && !raw {
				f.Start, f.End = positions[f.Start], positions[f.End]
			}
			findings = append(findings, Finding{Kind: Kind(f.DetectorName), Start: f.Start, End: f.End, Confidence: f.Confidence})
		}
	}
	for _, d := range s.custom {
		if scanCanceled(canceled) {
			return nil
		}
		findings = append(findings, d.Scan(data)...)
	}
	if scanCanceled(canceled) {
		return nil
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

func defaultKind(kind Kind) bool {
	switch kind { //nolint:exhaustive // Explicit opt-in families; the remaining built-ins retain their defaults.
	case KindHighEntropy, KindUSSSN, KindUSITIN, KindUKNINO, KindUKNHS, KindIndiaAadhaar, KindIndiaPAN, KindBrazilCPF, KindBrazilCNPJ, KindChinaResidentID, KindKoreaRRN, KindCanadaSIN:
		return false
	default:
		return true
	}
}

func scanCanceled(canceled func() error) bool {
	return canceled != nil && canceled() != nil
}

func normalizedScanInput(data []byte) (normalized []byte, positions []int) {
	decoded, positions := decodePercent(data)
	normalized, tokenPositions := detect.RemoveTokenSeparators(decoded)
	if tokenPositions == nil {
		return decoded, positions
	}
	if positions != nil {
		for i, pos := range tokenPositions {
			tokenPositions[i] = positions[pos]
		}
	}
	return normalized, tokenPositions
}
