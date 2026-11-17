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
// Unknown kinds panic. The supplied slice is copied.
func WithKinds(kinds ...Kind) ScannerOption {
	selected := make(map[Kind]bool, len(kinds))
	for _, kind := range kinds {
		known := false
		for _, d := range builtins(nil) {
			if Kind(d.Name()) == kind {
				known = true
				break
			}
		}
		if !known {
			panic("embargo: unknown built-in kind")
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
// For example, 0.7 excludes PAN checksum failures (0.6) and numeric candidates
// with attached business labels (0.4), at the risk of missing mislabeled secrets.
// It also excludes bank-account findings (0.5–0.65) and some sort codes; choose
// thresholds for the selected kinds. Confidence is a heuristic, not a probability. Non-finite scores or values outside [0,1] panic.
func WithMinConfidence(threshold float64) ScannerOption {
	if !validScore(threshold) {
		panic("embargo: invalid minimum confidence")
	}
	return scannerOption(func(s *Scanner) { s.minConfidence = threshold })
}

func validScore(score float64) bool { return !math.IsNaN(score) && score >= 0 && score <= 1 }
