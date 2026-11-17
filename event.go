package embargo

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
	"github.com/nao1215/embargo/internal/saferecord"
)

const (
	maxEventBytes = 1 << 20
	maxDepth      = 64
	maxScanBytes  = 4 * maxEventBytes
)

type eventScanner struct {
	scanner   *Scanner
	remaining int
}

// Include the field name so context-based detectors can recognize, for example,
// {"cvv":123}. Translate findings back to value bytes before replacing them.
func (s *eventScanner) maskScalar(ctx context.Context, value, key string) (string, error) {
	masked, err := s.scanScalar(ctx, value, key)
	if err != nil {
		return masked, err
	}
	if value == "" || (value[0] != '-' && (value[0] < '0' || value[0] > '9')) {
		return masked, nil
	}
	canonical := canonicalInteger(value)
	if !canonical && !json.Valid([]byte(value)) {
		return masked, nil
	}
	if masked != value {
		return redactionMarker, nil
	}
	if canonical {
		// exactInteger would return the same spelling, which was just scanned.
		return masked, nil
	}
	integer, err := exactInteger(value)
	if err != nil {
		return "", err
	}
	if integer == "" || integer == value {
		return masked, nil
	}
	safe, err := s.scanScalar(ctx, integer, key)
	if err != nil {
		return "", err
	}
	if safe != integer {
		return redactionMarker, nil
	}
	return masked, nil
}

// canonicalInteger reports whether text is -?(0|[1-9][0-9]*) other than -0,
// the spellings that exactInteger returns unchanged.
func canonicalInteger(text string) bool {
	digits := strings.TrimPrefix(text, "-")
	if digits == "" || (digits[0] == '0' && (len(digits) > 1 || len(text) > 1)) {
		return false
	}
	for i := range len(digits) {
		if !ascii.IsDigit(digits[i]) {
			return false
		}
	}
	return true
}

func (s *eventScanner) scanScalar(ctx context.Context, value, key string) (string, error) {
	scratch := s.scanner.takeScratch()
	defer s.scanner.returnScratch(scratch)
	findings, err := scalarFindings(ctx, s, scratch, value, key)
	if err != nil {
		return "", err
	}
	return maskOwned(value, findings, redact), nil
}

// maskBytes is maskScalar for bytes that usually stay unchanged: the value
// becomes a string only when it is numeric-looking or has findings. A false
// changed result means value itself is the masked output.
func (s *eventScanner) maskBytes(ctx context.Context, value []byte, key string) (masked string, changed bool, err error) {
	if len(value) > 0 && (value[0] == '-' || ascii.IsDigit(value[0])) {
		text := string(value)
		masked, err = s.maskScalar(ctx, text, key)
		return masked, masked != text, err
	}
	scratch := s.scanner.takeScratch()
	defer s.scanner.returnScratch(scratch)
	findings, err := scalarFindings(ctx, s, scratch, value, key)
	if err != nil || len(findings) == 0 {
		return "", false, err
	}
	text := string(value)
	masked = maskOwned(text, findings, redact)
	return masked, masked != text, nil
}

// scalarFindings scans "key: value" and returns the value's findings in value
// offsets. The budget is charged before any buffer is filled or detector runs.
func scalarFindings[T string | []byte](ctx context.Context, s *eventScanner, scratch *scanScratch, value T, key string) ([]Finding, error) {
	if ctx.Err() != nil {
		return nil, saferecord.ErrCanceled
	}
	prefixBytes := 0
	if key != "" {
		prefixBytes = len(key) + len(": ")
	}
	if prefixBytes > s.remaining || len(value) > s.remaining-prefixBytes {
		return nil, saferecord.ErrSizeLimit
	}
	s.remaining -= prefixBytes + len(value)
	text := slices.Grow(scratch.text[:0], prefixBytes+len(value))
	if prefixBytes > 0 {
		text = append(append(text, key...), ": "...)
	}
	text = append(text, value...)
	findings := s.scanner.scanAppend(scratch.findings[:0], text, ctx.Err)
	// Keep grown storage for the next user; the returned spans alias findings.
	scratch.text, scratch.findings = text, findings
	if ctx.Err() != nil {
		return nil, saferecord.ErrCanceled
	}
	if prefixBytes == 0 {
		return findings, nil
	}
	// Findings are fresh validated results; shift the value's spans in place.
	spans := findings[:0]
	for _, finding := range findings {
		if finding.End <= prefixBytes {
			continue
		}
		finding.Start = max(0, finding.Start-prefixBytes)
		finding.End -= prefixBytes
		spans = append(spans, finding)
	}
	return spans, nil
}

// A finding must cross the last join; detecting an ancestor alone does not hide descendants.
func (s *eventScanner) joinedKeySensitive(ctx context.Context, path string, boundary int) (bool, error) {
	if len(path) > s.remaining {
		return false, saferecord.ErrSizeLimit
	}
	s.remaining -= len(path)
	findings := s.scanner.scan([]byte(path), ctx.Err)
	if ctx.Err() != nil {
		return false, saferecord.ErrCanceled
	}
	for _, f := range findings {
		if f.Start < boundary && f.End > boundary+1 {
			return true, nil
		}
	}
	return false, nil
}
