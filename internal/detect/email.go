package detect

import (
	"slices"

	"github.com/nao1215/embargo/internal/ascii"
)

// Email implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindEmail.
type Email struct{}

// NewEmail recognizes ASCII local parts and dotted domain names.
func NewEmail() *Email {
	return &Email{}
}

// Name returns "email".
func (d *Email) Name() DetectorName {
	return NameEmail
}

// Hints returns the pre-filter substrings for [Email].
func (d *Email) Hints() [][]byte {
	return [][]byte{
		[]byte("@"),
	}
}

// Scan returns matches in data using the rules documented on [Email].
func (d *Email) Scan(data []byte) []Finding {
	var findings []Finding
	boundary := 0

	for i := range data {
		if data[i] != '@' {
			continue
		}

		// An accepted domain is a boundary for the next local part. Walking
		// through it can reject an adjacent address or create overlapping spans.
		localStart, ok := findLocalPartStart(data[boundary:], i-boundary)
		localStart += boundary
		if !ok {
			continue
		}

		domainEnd, domain, ok := findDomainEnd(data, i)
		if !ok {
			continue
		}

		if isSCPRemote(data, localStart, i, domainEnd) {
			continue
		}

		tld, ok := validateTLD(domain)
		if !ok {
			continue
		}

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        localStart,
			End:          domainEnd,
			Confidence:   emailConfidence(tld, domain),
		})
		boundary = domainEnd
	}

	return findings
}

// isSCPRemote reports whether git@host: followed by a path is an SCP-style Git
// remote rather than an email address.
func isSCPRemote(data []byte, localStart, at, domainEnd int) bool {
	return string(data[localStart:at]) == "git" && domainEnd+1 < len(data) && data[domainEnd] == ':' && !urlDelimiter(data[domainEnd+1])
}

// emailConfidence scores an accepted address from a base, a known TLD and a
// domain without consecutive dots.
func emailConfidence(tld, domain []byte) float64 {
	// Integer tenths avoid losing an inclusive documented threshold to rounding.
	const basePoints, tldPoints, structurePoints, scoreScale = 7, 2, 1, 10
	points := basePoints
	if isKnownTLD(tld) {
		points += tldPoints
	}
	// Structural check: no consecutive dots in domain.
	if !hasConsecutiveDots(domain) {
		points += structurePoints
	}
	return float64(points) / scoreScale
}

// findLocalPartStart walks backward from atIdx to find the start of the local
// part. It returns (start, false) if the local part is empty, starts or ends
// with '.', or contains consecutive dots.
func findLocalPartStart(data []byte, atIdx int) (start int, ok bool) {
	localStart := atIdx
	for localStart > 0 && isLocalPartChar(data[localStart-1]) {
		localStart--
	}
	// Exclude the hexadecimal digits of a preceding encoded separator.
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if localStart+2 <= atIdx && encodedSeparatorBefore(data, localStart+2) {
		localStart += 2
	}
	// Local part must not be empty and must not start/end with '.'.
	if localStart == atIdx {
		return 0, false
	}
	if data[localStart] == '.' || data[atIdx-1] == '.' {
		return 0, false
	}
	// Local part must not contain consecutive dots (RFC 5321).
	if hasConsecutiveDots(data[localStart:atIdx]) {
		return 0, false
	}
	return localStart, true
}

// findDomainEnd walks forward from atIdx+1 to find the end of the domain part,
// trimming any trailing '.' and '-' characters. It returns (0, nil, false) if
// the domain is empty after trimming.
func findDomainEnd(data []byte, atIdx int) (end int, domain []byte, ok bool) {
	domainEnd := atIdx + 1
	for domainEnd < len(data) && isDomainChar(data[domainEnd]) {
		domainEnd++
	}
	// Trim trailing '.' if any.
	for domainEnd > atIdx+1 && data[domainEnd-1] == '.' {
		domainEnd--
	}
	// Trim trailing '-' if any.
	for domainEnd > atIdx+1 && data[domainEnd-1] == '-' {
		domainEnd--
	}

	domain = data[atIdx+1 : domainEnd]
	if len(domain) == 0 {
		return 0, nil, false
	}
	return domainEnd, domain, true
}

// validateTLD finds the last '.' in domain, checks that the TLD is at least 2
// characters long and composed entirely of alphabetic characters, and verifies
// that the domain does not start with '.' and no domain label starts or ends
// with '-'. It returns (nil, false) if any
// of these checks fail.
func validateTLD(domain []byte) (tld []byte, ok bool) {
	// Domain must not start with '.': the first label would be empty, as in
	// "user@.com", which names a TLD but no domain.
	if domain[0] == '.' {
		return nil, false
	}
	// Domain must contain at least one '.'.
	dotIdx := -1
	for k, d := range slices.Backward(domain) {
		if d == '.' {
			dotIdx = k
			break
		}
	}
	if dotIdx < 0 {
		return nil, false
	}

	// TLD must be at least 2 characters.
	tld = domain[dotIdx+1:]
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(tld) < 2 {
		return nil, false
	}
	// TLD must be all alpha.
	for _, b := range tld {
		if !ascii.IsAlpha(b) {
			return nil, false
		}
	}
	// Domain labels must not start or end with '-' (RFC 5321).
	if hasInvalidLabelBoundary(domain) {
		return nil, false
	}
	return tld, true
}

// isLocalPartChar reports whether b is a valid character in the local part
// of an email address (before the '@').
func isLocalPartChar(b byte) bool {
	return isTokenByte(b) || b == '.' || b == '+'
}

// isDomainChar reports whether b is a valid character in the domain part
// of an email address (after the '@').
func isDomainChar(b byte) bool {
	return ascii.IsAlphaNum(b) || b == '.' || b == '-'
}

// hasConsecutiveDots reports whether data contains "..".
func hasConsecutiveDots(data []byte) bool {
	for i := 1; i < len(data); i++ {
		if data[i] == '.' && data[i-1] == '.' {
			return true
		}
	}
	return false
}

// isKnownTLD checks whether the TLD is one of the commonly known TLDs.
// The comparison is case-insensitive. This is a non-exhaustive list used
// only for confidence scoring.
func isKnownTLD(tld []byte) bool {
	known := []string{
		"com", "org", "net", "edu", "gov", "mil", "int",
		"io", "co", "us", "uk", "de", "fr", "jp", "cn", "kr", "au", "ca",
		"info", "biz", "name", "pro", "museum", "coop", "aero",
	}
	s := ascii.LowerString(string(tld))
	return slices.Contains(known, s)
}

// hasInvalidLabelBoundary reports whether any domain label starts or ends
// with '-'. For example, "-example.com" or "sub.example-.com" have invalid
// labels per RFC 5321.
func hasInvalidLabelBoundary(domain []byte) bool {
	if len(domain) == 0 {
		return false
	}
	// First label must not start with '-'.
	if domain[0] == '-' {
		return true
	}
	for i := 1; i < len(domain); i++ {
		// Label ending with '-' (dash before dot).
		if domain[i] == '.' && domain[i-1] == '-' {
			return true
		}
		// Label starting with '-' (dash after dot).
		if domain[i] == '-' && domain[i-1] == '.' {
			return true
		}
	}
	return false
}
