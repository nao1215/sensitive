package detector

// EmailDetail holds email-specific detail information for an email finding.
type EmailDetail struct {
	// Local is the local part of the email address (before '@').
	Local string
	// Domain is the domain part of the email address (after '@').
	Domain string
}

// Email detects email addresses in text using heuristic validation.
//
// This is NOT a strict RFC 5321/5322 parser. It uses practical rules that
// cover the vast majority of real-world email addresses while keeping false
// positives low. Notably, it does not support quoted local parts, IP-literal
// domains, or internationalized email addresses (EAI/RFC 6530).
//
// Detection uses '@' as a pivot point rather than a regular expression:
//  1. Scan for '@' characters in the input
//  2. Walk backward from '@' to identify the local part (allowed: alphanumeric,
//     '.', '+', '-', '_'; must not start or end with '.')
//  3. Walk forward from '@' to identify the domain part (allowed: alphanumeric,
//     '.', '-')
//  4. Validate that the local part is non-empty, the domain contains at least
//     one '.', and the TLD is at least 2 alphabetic characters
//
// Confidence is calculated as:
//   - Basic structure match: 0.7
//   - + Known TLD (case-insensitive check): +0.2 (= 0.9)
//   - + No consecutive dots in domain: +0.1 (= 1.0)
type Email struct{}

// NewEmail creates a new Email detector.
func NewEmail() *Email {
	return &Email{}
}

// Name returns "email".
func (d *Email) Name() DetectorName {
	return NameEmail
}

// Hints returns byte sequences that may indicate the presence of an email address.
// Every email address contains an '@' character.
func (d *Email) Hints() [][]byte {
	return [][]byte{
		[]byte("@"),
	}
}

// Scan examines data for email addresses and returns findings.
// It scans for '@' characters and validates the surrounding local and domain parts.
func (d *Email) Scan(data []byte) []Finding {
	var findings []Finding

	for i := range data {
		if data[i] != '@' {
			continue
		}

		// Walk backward to find the start of the local part.
		localStart := i
		for localStart > 0 && isLocalPartChar(data[localStart-1]) {
			localStart--
		}
		// Local part must not be empty and must not start/end with '.'.
		if localStart == i {
			continue
		}
		if data[localStart] == '.' || data[i-1] == '.' {
			continue
		}
		// Local part must not contain consecutive dots (RFC 5321).
		if hasConsecutiveDots(data[localStart:i]) {
			continue
		}

		// Walk forward to find the end of the domain part.
		domainEnd := i + 1
		for domainEnd < len(data) && isDomainChar(data[domainEnd]) {
			domainEnd++
		}
		// Trim trailing '.' if any.
		for domainEnd > i+1 && data[domainEnd-1] == '.' {
			domainEnd--
		}
		// Trim trailing '-' if any.
		for domainEnd > i+1 && data[domainEnd-1] == '-' {
			domainEnd--
		}

		domain := data[i+1 : domainEnd]
		if len(domain) == 0 {
			continue
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
			continue
		}

		// TLD must be at least 2 characters.
		tld := domain[dotIdx+1:]
		if len(tld) < 2 {
			continue
		}
		// TLD must be all alpha.
		allAlpha := true
		for _, b := range tld {
			if !isAlpha(b) {
				allAlpha = false
				break
			}
		}
		if !allAlpha {
			continue
		}
		// Domain labels must not start or end with '-' (RFC 5321).
		if hasInvalidLabelBoundary(domain) {
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
