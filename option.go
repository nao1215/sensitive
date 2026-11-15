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
		for _, d := range builtins() {
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
	return scannerOption(func(s *Scanner) { s.kinds = selected })
}

// WithAll selects every built-in, including IP addresses and context-based detectors.
func WithAll() ScannerOption { return scannerOption(func(s *Scanner) { s.kinds = nil }) }

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

// WithMinConfidence keeps findings at or above min. Non-finite scores or values outside [0,1] panic.
func WithMinConfidence(threshold float64) ScannerOption {
	if !validScore(threshold) {
		panic("embargo: invalid minimum confidence")
	}
	return scannerOption(func(s *Scanner) { s.minConfidence = threshold })
}

func validScore(score float64) bool { return !math.IsNaN(score) && score >= 0 && score <= 1 }
