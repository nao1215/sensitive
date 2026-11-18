package embargo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

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
	masked, asNumber, err := s.scanScalar(ctx, value, key)
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
		return asNumber, nil
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
	safe, _, err := s.scanScalar(ctx, integer, key)
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

// scanScalar masks value's findings. asNumber is the result to use when value
// is a JSON number: the masked text when one finding covers all of value, so no
// digits outside a finding survive, and the marker otherwise.
func (s *eventScanner) scanScalar(ctx context.Context, value, key string) (masked, asNumber string, err error) {
	scratch := s.scanner.takeScratch()
	defer s.scanner.returnScratch(scratch)
	findings, err := scalarFindings(ctx, s, scratch, value, key)
	if err != nil {
		return "", "", err
	}
	if len(findings) == 0 {
		if hidden, err := encodedTextSensitive(ctx, s, value, key); err != nil || hidden {
			return redactionMarker, redactionMarker, err
		}
	}
	whole := slices.ContainsFunc(findings, func(f Finding) bool { return f.Start == 0 && f.End == len(value) })
	masked = maskOwned(value, findings, s.scanner.replacer())
	if whole {
		return masked, masked, nil
	}
	return masked, redactionMarker, nil
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
	if err != nil {
		return "", false, err
	}
	if len(findings) == 0 {
		hidden, err := encodedTextSensitive(ctx, s, value, key)
		return redactionMarker, hidden, err
	}
	text := string(value)
	masked = maskOwned(text, findings, s.scanner.replacer())
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
	findings := s.scanner.scanField(scratch.findings[:0], text, prefixBytes, ctx.Err)
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

// encoding/json and zap.Binary write a []byte as padded standard base64, so a
// byte field holding a token reaches the scalar policy as an opaque string.
// Values of this length range are decoded and scanned when the bytes are text;
// binary data such as an image is not text and is never scanned.
const (
	minEncodedText = 20
	maxEncodedText = 8 << 10
)

// encodedTextSensitive reports findings in value decoded as padded standard
// base64, charged to the scan budget, when the decoded bytes are printable
// UTF-8 text.
func encodedTextSensitive[T string | []byte](ctx context.Context, s *eventScanner, value T, key string) (bool, error) {
	if !standardBase64(value) {
		return false, nil
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	n, err := base64.StdEncoding.Decode(decoded, []byte(value))
	if err != nil || !printableText(decoded[:n]) {
		return false, nil
	}
	scratch := s.scanner.takeScratch()
	defer s.scanner.returnScratch(scratch)
	findings, err := scalarFindings(ctx, s, scratch, decoded[:n], key)
	return len(findings) > 0, err
}

// standardBase64 reports a length and alphabet that padded standard base64
// can have; the decoder checks the padding.
func standardBase64[T string | []byte](value T) bool {
	const quantum = 4
	if len(value) < minEncodedText || len(value) > maxEncodedText || len(value)%quantum != 0 {
		return false
	}
	for i := range len(value) {
		if c := value[i]; !ascii.IsAlphaNum(c) && c != '+' && c != '/' && c != '=' {
			return false
		}
	}
	return true
}

// printableText reports valid UTF-8 whose runes are printable or tab, CR and LF.
func printableText(data []byte) bool {
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size <= 1 {
			return false
		}
		if !unicode.IsPrint(r) && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
		data = data[size:]
	}
	return true
}
