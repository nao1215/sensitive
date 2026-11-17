package embargo

import (
	"bytes"
	"cmp"
	"slices"
	"sync"

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
	buffers       *sync.Pool
	results       *sync.Pool
	keys          *keyCache
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
	var matchKey func(string) bool
	if s.sensitiveKeys != nil {
		matchKey = s.sensitiveKey
	}
	for _, d := range builtins(matchKey) {
		if (s.kinds == nil && (s.allKinds || defaultKind(Kind(d.Name())))) || s.kinds[Kind(d.Name())] {
			s.detectors = append(s.detectors, d)
		}
	}
	s.hintCache = buildHintCache(s.detectors)
	if len(s.detectors) > 1 {
		s.buildDispatch()
	}
	// Custom detectors receive the scanned bytes and may keep them or answer
	// differently each time, so only built-in selections, which never retain
	// input and always return the same findings, reuse buffers and key results.
	if len(s.custom) == 0 {
		s.buffers = &sync.Pool{New: func() any { return new([]byte) }}
		s.results = &sync.Pool{New: func() any { return new([]Finding) }}
		s.keys = &keyCache{}
	}
	return s
}

// largestPooledBuffer keeps one huge scalar from pinning its buffer in the pool.
const largestPooledBuffer = 64 << 10

// takeBuffer returns an empty buffer with room for size bytes. Scanners with
// custom detectors, zero-value scanners and large sizes get a fresh one.
func (s *Scanner) takeBuffer(size int) *[]byte {
	if s.buffers == nil || size > largestPooledBuffer {
		buffer := make([]byte, 0, size)
		return &buffer
	}
	buffer, ok := s.buffers.Get().(*[]byte)
	if !ok {
		panic("embargo: invalid scan buffer")
	}
	*buffer = slices.Grow((*buffer)[:0], size)
	return buffer
}

// takeFindings returns empty storage for internal findings that the caller
// consumes before returnFindings; findings that leave the package are never pooled.
func (s *Scanner) takeFindings() *[]Finding {
	if s.results == nil {
		return new([]Finding)
	}
	findings, ok := s.results.Get().(*[]Finding)
	if !ok {
		panic("embargo: invalid findings buffer")
	}
	return findings
}

// returnFindings keeps storage grown by its last user for the next scan.
func (s *Scanner) returnFindings(findings *[]Finding, used []Finding) {
	if s.results == nil || cap(used) > maxPooledFindings {
		return
	}
	*findings = used[:0]
	s.results.Put(findings)
}

// maxPooledFindings keeps a scan with many findings from pinning its storage.
const maxPooledFindings = 64

// returnBuffer keeps a buffer, grown by its last user, for the next scan.
func (s *Scanner) returnBuffer(buffer *[]byte, used []byte) {
	if s.buffers == nil || cap(used) > largestPooledBuffer {
		return
	}
	*buffer = used[:0]
	s.buffers.Put(buffer)
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
// escapes (%HH); KindCredential keeps original URL/DSN delimiters and also scans
// normalized assignments.
// Literal + and invalid escapes are preserved; offsets always refer
// to original bytes. KindCredential also scans up to four Go/JSON quote and
// backslash escape layers, including hexadecimal and Unicode quote escapes. Other encodings are not decoded. Custom detectors receive
// the original bytes. Invalid custom findings panic with a fixed message.
func (s *Scanner) Scan(data []byte) []Finding {
	return s.scan(data, nil)
}

func (s *Scanner) scan(data []byte, canceled func() error) []Finding {
	return s.scanAppend(nil, data, canceled)
}

// scanAppend is scan that reuses dst's storage for the findings it returns.
func (s *Scanner) scanAppend(dst []Finding, data []byte, canceled func() error) []Finding {
	if scanCanceled(canceled) || len(data) == 0 {
		return nil
	}
	if !s.initialized {
		return NewScanner().scanAppend(dst, data, canceled)
	}
	view := detect.View{Raw: data, Data: data}
	if len(s.detectors) > 0 {
		view = detect.NewView(data)
	}
	return s.scanInput(dst, view, canceled)
}

// scanInput shares the normalized view with streaming frame recognition.
func (s *Scanner) scanInput(dst []Finding, view detect.View, canceled func() error) []Finding {
	if len(view.Raw) == 0 || scanCanceled(canceled) {
		return nil
	}
	selected := s.selectDetectors(view.Data)
	findings := dst[:0]
	for i, d := range s.detectors {
		if scanCanceled(canceled) {
			return nil
		}
		if selected&(1<<i) == 0 {
			continue
		}
		findings = appendBuiltinFindings(findings, d, view)
	}
	for _, d := range s.custom {
		if scanCanceled(canceled) {
			return nil
		}
		findings = append(findings, d.Scan(view.Raw)...)
	}
	if scanCanceled(canceled) {
		return nil
	}
	return s.filterFindings(findings, len(view.Raw))
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

// appendBuiltinFindings converts one detector result, already in original offsets, to public findings.
func appendBuiltinFindings(findings []Finding, d detect.Detector, view detect.View) []Finding {
	for _, f := range detect.ScanView(d, view) {
		findings = append(findings, Finding{Kind: Kind(f.DetectorName), Start: f.Start, End: f.End, Confidence: f.Confidence})
	}
	return findings
}

// Validate all findings before applying the inclusive confidence threshold and stable ordering.
func (s *Scanner) filterFindings(findings []Finding, inputLength int) []Finding {
	result := findings[:0]
	for _, f := range findings {
		if f.Kind == "" || f.Start < 0 || f.End <= f.Start || f.End > inputLength || !validScore(f.Confidence) {
			panic("embargo: invalid detector finding")
		}
		if f.Confidence >= s.minConfidence {
			result = append(result, f)
		}
	}
	slices.SortStableFunc(result, compareFindings)
	return result
}
