package detector

// EmailDetail holds email-specific detail information for an email finding.
type EmailDetail struct {
	// Local is the local part of the email address (before '@').
	Local string
	// Domain is the domain part of the email address (after '@').
	Domain string
}

// Email detects addresses heuristically, without quoted local parts, IP-literal domains, or internationalized addresses (EAI/RFC 6530).
//
//  1. Find @, then scan backward over alphanumerics and .+-_ for the local part and forward over alphanumerics and .- for the domain.
//  2. Require a nonempty local part without leading/trailing dots, a domain containing a dot but not starting with one, and an alphabetic TLD of at least two characters.
//  3. Score the structure as 0.7, add 0.2 for a known TLD (case-insensitive), and add 0.1 for a domain without consecutive dots.
type Email struct{}

// NewEmail creates a new Email detector.
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

	for i := range data {
		if data[i] != '@' {
			continue
		}

		localStart, ok := findLocalPartStart(data, i)
		if !ok {
			continue
		}

		domainEnd, domain, ok := findDomainEnd(data, i)
		if !ok {
			continue
		}

		tld, ok := validateTLD(domain)
		if !ok {
			continue
		}

		confidence := 0.7
		if isKnownTLD(tld) {
			confidence += 0.2
		}
		// Structural check: no consecutive dots in domain.
		if !hasConsecutiveDots(domain) {
			confidence += 0.1
		}

		raw := string(data[localStart:domainEnd])
		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        localStart,
			End:          domainEnd,
			Confidence:   confidence,
			RawValue:     raw,
			Detail: &EmailDetail{
				Local:  string(data[localStart:i]),
				Domain: string(domain),
			},
		})
	}

	return findings
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
	for k := len(domain) - 1; k >= 0; k-- {
		if domain[k] == '.' {
			dotIdx = k
			break
		}
	}
	if dotIdx < 0 {
		return nil, false
	}

	// TLD must be at least 2 characters.
	tld = domain[dotIdx+1:]
	if len(tld) < 2 {
		return nil, false
	}
	// TLD must be all alpha.
	for _, b := range tld {
		if !isAlpha(b) {
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
	return isAlphaNum(b) || b == '.' || b == '+' || b == '-' || b == '_'
}

// isDomainChar reports whether b is a valid character in the domain part
// of an email address (after the '@').
func isDomainChar(b byte) bool {
	return isAlphaNum(b) || b == '.' || b == '-'
}

// isAlpha reports whether b is an ASCII letter.
func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isAlphaNum reports whether b is an ASCII alphanumeric character.
func isAlphaNum(b byte) bool {
	return isAlpha(b) || isDigit(b)
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
	s := toLowerASCIIString(string(tld))
	for _, k := range known {
		if s == k {
			return true
		}
	}
	return false
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

// toLowerASCIIString converts ASCII uppercase letters in a string to lowercase.
func toLowerASCIIString(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
