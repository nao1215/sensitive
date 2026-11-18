package embargo

import (
	"math"
	"reflect"
)

// ScannerOption configures a scanner at construction time.
type (
	ScannerOption interface{ apply(*Scanner) }
	scannerOption func(*Scanner)
)

func (o scannerOption) apply(s *Scanner) { o(s) }

// WithKinds replaces the built-in selection. No kinds selects none; custom detectors remain.
// An unknown kind panics; the message quotes it and suggests the nearest
// built-in only when it is a likely misspelling, within two edits of one.
// The supplied slice is copied.
func WithKinds(kinds ...Kind) ScannerOption {
	selected := make(map[Kind]bool, len(kinds))
	known := make(map[Kind]bool)
	for _, d := range builtins(nil) {
		known[Kind(d.Name())] = true
	}
	for _, kind := range kinds {
		if !known[kind] {
			panic("embargo: unknown built-in kind" + quotedKind(kind, known))
		}
		selected[kind] = true
	}
	return scannerOption(func(s *Scanner) { s.kinds = selected; s.allKinds = false })
}

// WithAll enables national identifiers from every supported country and unlabelled entropy candidates.
// WithKinds avoids scanning for formats the application never handles and usually costs less.
// Measurements and the recall tradeoff are in https://github.com/nao1215/embargo/blob/main/doc/benchmarks.md.
func WithAll() ScannerOption {
	return scannerOption(func(s *Scanner) { s.kinds = nil; s.allKinds = true })
}

// WithDetector appends a custom detector independently of the built-in selection.
// Nil and typed-nil detectors panic.
func WithDetector(d Detector) ScannerOption {
	if d == nil {
		panic("embargo: nil detector")
	}
	v := reflect.ValueOf(d)
	switch v.Kind() { //nolint:exhaustive // Only nil-capable kinds need IsNil; all other kinds are valid detector values.
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			panic("embargo: nil detector")
		}
	}
	return scannerOption(func(s *Scanner) { s.custom = append(s.custom, d) })
}

// WithMinConfidence keeps findings at or above threshold; the default is 0.
// For example, 0.7 excludes numeric candidates with attached business labels
// (0.4), at the risk of missing mislabeled secrets.
// It also excludes bank-account findings (0.5–0.65) and some sort codes; choose
// thresholds for the selected kinds. Confidence is a heuristic, not a probability. Non-finite scores or values outside [0,1] panic.
func WithMinConfidence(threshold float64) ScannerOption {
	if !validScore(threshold) {
		panic("embargo: invalid minimum confidence")
	}
	return scannerOption(func(s *Scanner) { s.minConfidence = threshold })
}

func validScore(score float64) bool { return !math.IsNaN(score) && score >= 0 && score <= 1 }

// quotedKind names a misspelled kind and its nearest built-in, as in
// ` "emial" (did you mean "email"?)`, when the two differ by at most two edits.
// Other values are not repeated, so a panic never echoes arbitrary caller data.
func quotedKind(kind Kind, known map[Kind]bool) string {
	const maxEdits = 2
	best, bestDistance := Kind(""), maxEdits+1
	for candidate := range known {
		if d := editDistance(string(kind), string(candidate)); d < bestDistance || (d == bestDistance && candidate < best) {
			best, bestDistance = candidate, d
		}
	}
	if best == "" {
		return ""
	}
	return ` "` + string(kind) + `" (did you mean "` + string(best) + `"?)`
}

// editDistance is the Levenshtein distance between two short ASCII names.
func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := range len(a) {
		current := make([]int, len(b)+1)
		current[0] = i + 1
		for j := range len(b) {
			cost := 1
			if a[i] == b[j] {
				cost = 0
			}
			current[j+1] = min(previous[j+1]+1, current[j]+1, previous[j]+cost)
		}
		previous = current
	}
	return previous[len(b)]
}
