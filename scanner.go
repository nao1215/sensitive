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
	maskFunc      func(Kind, string) string
	scratch       *sync.Pool
	keys          *keyCache
	credential    detect.Detector
	hintIndex     [256][]dispatchHint
	follow        [256]byteSet
	minConfidence float64
	unconditional uint64
	labelMask     uint64
	keywordMask   uint64
	credentialBit uint64
	initialized   bool
	allKinds      bool
	noDefaultKeys bool
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

// NewScanner starts with 26 built-ins; the additional country families and KindHighEntropy are opt-in.
// WithAll enables all 38 families; WithKinds selects the regions and formats an application handles.
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
	if s.sensitiveKeys != nil || s.noDefaultKeys {
		matchKey = s.sensitiveKey
	}
	for _, d := range builtins(matchKey) {
		if (s.kinds == nil && (s.allKinds || defaultKind(Kind(d.Name())))) || s.kinds[Kind(d.Name())] {
			s.detectors = append(s.detectors, d)
		}
	}
	s.hintCache = buildHintCache(s.detectors)
	s.indexLabelReaders()
	if len(s.detectors) > 1 {
		s.buildDispatch()
	}
	// Custom detectors receive the scanned bytes and may keep them or answer
	// differently each time, so only built-in selections, which never retain
	// input and always return the same findings, reuse buffers and key results.
	if len(s.custom) == 0 {
		s.scratch = &sync.Pool{New: func() any { return &scanScratch{text: nil, findings: nil} }}
		s.keys = &keyCache{}
	}
	return s
}

// scanScratch holds the "key: value" bytes of one scalar scan and the findings
// the caller consumes before returning it; findings that leave the package are
// never pooled.
type scanScratch struct {
	text     []byte
	findings []Finding
}

// Limits that keep one huge or finding-heavy scalar from pinning its storage.
const (
	largestPooledBuffer = 64 << 10
	maxPooledFindings   = 64
)

// takeScratch returns empty scratch storage. Scanners with custom detectors and
// zero-value scanners get fresh storage.
func (s *Scanner) takeScratch() *scanScratch {
	if s.scratch == nil {
		return &scanScratch{text: nil, findings: nil}
	}
	scratch, ok := s.scratch.Get().(*scanScratch)
	if !ok {
		panic("embargo: invalid scan scratch")
	}
	return scratch
}

// returnScratch keeps storage, grown by its last user, for the next scan.
func (s *Scanner) returnScratch(scratch *scanScratch) {
	if s.scratch == nil || cap(scratch.text) > largestPooledBuffer || cap(scratch.findings) > maxPooledFindings {
		return
	}
	scratch.text, scratch.findings = scratch.text[:0], scratch.findings[:0]
	s.scratch.Put(scratch)
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

// defaultScanner is the NewScanner policy that a zero Scanner uses. It is
// built once and shared: the policy is immutable and the built-in detectors
// never retain input, so sharing it is what NewScanner callers already do.
//
//nolint:gochecknoglobals // One immutable default policy instead of a rebuild per call.
var defaultScanner = sync.OnceValue(func() *Scanner { return NewScanner() })

// scanAppend is scan that reuses dst's storage for the findings it returns.
func (s *Scanner) scanAppend(dst []Finding, data []byte, canceled func() error) []Finding {
	if scanCanceled(canceled) || len(data) == 0 {
		return nil
	}
	if !s.initialized {
		return defaultScanner().scanAppend(dst, data, canceled)
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
		if selected&(1<<i) == 0 {
			continue
		}
		if scanCanceled(canceled) {
			return nil
		}
		findings = appendBuiltinFindings(findings, d, view)
	}
	return s.finishScan(findings, view.Raw, canceled)
}

// indexLabelReaders marks the detectors that read a field name before a value.
func (s *Scanner) indexLabelReaders() {
	for i, d := range s.detectors {
		if detect.ReadsLabel(d) {
			s.labelMask |= 1 << i
		}
		if detect.KeywordHinted(d) {
			s.keywordMask |= 1 << i
		}
		if d.Name() == detect.NameCredential {
			s.credential, s.credentialBit = d, 1<<i
		}
	}
}

// scanField scans a structured value after its field name: text is
// "key: value" and prefix is the length of "key: ". Dispatch reads the value
// and, for detectors whose hints are keywords, the key; a candidate start in
// the key alone selects nothing, since only value findings are kept. Selected
// detectors that read labels scan the whole text, except Credential, which
// reads the key only when it is a credential key; every other detector scans
// the value alone. Findings are in text offsets, as from scanAppend.
func (s *Scanner) scanField(dst []Finding, text []byte, prefix int, canceled func() error) []Finding {
	if !s.initialized {
		return defaultScanner().scanField(dst, text, prefix, canceled)
	}
	if prefix == 0 || len(s.detectors) == 0 {
		return s.scanAppend(dst, text, canceled)
	}
	if scanCanceled(canceled) {
		return nil
	}
	value := detect.NewView(text[prefix:])
	selected, wholeText := s.selectField(text, prefix, value)
	var whole detect.View
	findings := dst[:0]
	for i, d := range s.detectors {
		bit := uint64(1) << i
		if selected&bit == 0 {
			continue
		}
		if scanCanceled(canceled) {
			return nil
		}
		if wholeText&bit == 0 {
			findings = appendShiftedFindings(findings, d, value, prefix)
			continue
		}
		if !detect.HasCandidate(d, value.Data) {
			continue
		}
		if whole.Raw == nil {
			whole = detect.NewView(text)
		}
		findings = appendBuiltinFindings(findings, d, whole)
	}
	return s.finishScan(findings, text, canceled)
}

// selectField returns the detectors a field selects and, among them, those
// that scan the whole "key: value" text rather than the value alone.
func (s *Scanner) selectField(text []byte, prefix int, value detect.View) (selected, wholeText uint64) {
	keyEnd := prefix - len(": ")
	key, ok := s.cachedField(text[:keyEnd])
	if !ok {
		key = s.keyField(text, keyEnd)
	}
	selected = s.selectDetectors(value.Data) | key.selected
	wholeText = s.labelMask &^ s.credentialBit
	if key.assigns && detect.AssignsValue(key.credential, text, keyEnd) {
		selected |= s.credentialBit
		wholeText |= s.credentialBit
	}
	return selected, wholeText
}

// fieldKey is the part of a field's detector selection that depends on its
// key alone, so repeated keys reuse it from the key cache.
type fieldKey struct {
	// credential is the normalized credential key name when assigns is set.
	credential string
	// selected holds the keyword-hinted detectors whose keywords occur in the key.
	selected uint64
	assigns  bool
}

// keyField computes fieldKey for the key that ends at keyEnd, where text
// has the separator of "key: value".
func (s *Scanner) keyField(text []byte, keyEnd int) fieldKey {
	key := fieldKey{selected: s.selectDetectors(text[:keyEnd]) & s.keywordMask}
	key.credential, key.assigns = detect.CredentialKeyName(s.credential, text, keyEnd)
	return key
}

// cachedField returns the cached fieldKey of a key that maskCached has kept.
func (s *Scanner) cachedField(key []byte) (fieldKey, bool) {
	if !cacheableKey(s, key) {
		return fieldKey{}, false
	}
	result, ok := s.keys.loadBytes(key)
	return result.field, ok
}

// finishScan appends custom detector findings for data and validates them all.
func (s *Scanner) finishScan(findings []Finding, data []byte, canceled func() error) []Finding {
	for _, d := range s.custom {
		if scanCanceled(canceled) {
			return nil
		}
		findings = append(findings, d.Scan(data)...)
	}
	if scanCanceled(canceled) {
		return nil
	}
	return s.filterFindings(findings, len(data))
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

// appendShiftedFindings appends d's findings in view, moved by offset bytes.
func appendShiftedFindings(findings []Finding, d detect.Detector, view detect.View, offset int) []Finding {
	for _, f := range detect.ScanView(d, view) {
		findings = append(findings, Finding{Kind: Kind(f.DetectorName), Start: f.Start + offset, End: f.End + offset, Confidence: f.Confidence})
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
