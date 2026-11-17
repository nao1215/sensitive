package embargo

import (
	"context"
	"encoding/json"

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
	if value == "" || (value[0] != '-' && (value[0] < '0' || value[0] > '9')) || !json.Valid([]byte(value)) {
		return masked, nil
	}
	if masked != value {
		return redactionMarker, nil
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

func (s *eventScanner) scanScalar(ctx context.Context, value, key string) (string, error) {
	if ctx.Err() != nil {
		return "", saferecord.ErrCanceled
	}
	// Charge before allocating the prefix or invoking any detector.
	prefixBytes := 0
	if key != "" {
		prefixBytes = len(key) + len(": ")
	}
	if prefixBytes > s.remaining || len(value) > s.remaining-prefixBytes {
		return "", saferecord.ErrSizeLimit
	}
	s.remaining -= prefixBytes + len(value)
	if prefixBytes == 0 {
		findings := s.scanner.scan([]byte(value), ctx.Err)
		if ctx.Err() != nil {
			return "", saferecord.ErrCanceled
		}
		return Mask(value, findings), nil
	}
	findings := s.scanner.scan([]byte(key+": "+value), ctx.Err)
	if ctx.Err() != nil {
		return "", saferecord.ErrCanceled
	}
	spans := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.End <= prefixBytes {
			continue
		}
		finding.Start = max(0, finding.Start-prefixBytes)
		finding.End -= prefixBytes
		spans = append(spans, finding)
	}
	return Mask(value, spans), nil
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
