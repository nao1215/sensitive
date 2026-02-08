package detector

import "net"

// IPAddrDetail holds IP address-specific detail information.
type IPAddrDetail struct {
	// Version is the IP version: 4 for IPv4, 6 for IPv6.
	Version int
}

// IPAddr detects IP addresses (IPv4 and IPv6) in text.
//
// IPv4 detection:
//  1. Scan for digit sequences separated by '.'
//  2. Validate 4 octets, each 0-255
//
// IPv6 detection:
//  1. Scan for hex digit sequences separated by ':'
//  2. Validate structure (including '::' shorthand)
//
// Confidence: 0.8 for valid IP addresses.
type IPAddr struct{}

// NewIPAddr creates a new IP address detector.
func NewIPAddr() *IPAddr {
	return &IPAddr{}
}

// Name returns "ipaddr".
func (d *IPAddr) Name() DetectorName {
	return NameIPAddr
}

// Hints returns byte sequences for pre-filtering.
// IPv4 addresses contain '.', and IPv6 addresses contain ':'.
func (d *IPAddr) Hints() [][]byte {
	return [][]byte{
		[]byte("."),
		[]byte(":"),
	}
}

// Scan examines data for IP addresses and returns findings.
func (d *IPAddr) Scan(data []byte) []Finding {
	var findings []Finding

	i := 0
	for i < len(data) {
		// Try IPv4 first if we see a digit.
		if isDigit(data[i]) {
			if f, adv, ok := d.tryIPv4(data, i); ok {
				findings = append(findings, f)
				i = adv
				continue
			}
			// IPv4 failed — fall through to try IPv6 at the same position,
			// since decimal digits are also valid hex digits in IPv6 addresses.
		}

		// Try IPv6: hex digits or ':'.
		if isHexDigit(data[i]) || data[i] == ':' {
			f, adv, ok := d.tryIPv6(data, i)
			if ok {
				findings = append(findings, f)
			}
			i = adv
			continue
		}

		i++
	}

	return findings
}

// tryIPv4 attempts to parse an IPv4 address starting at data[i].
// Returns the finding, the advance position, and whether a valid IPv4 was found.
func (d *IPAddr) tryIPv4(data []byte, i int) (Finding, int, bool) {
	// Word boundary: reject if preceded by alphanumeric, '.', or '_'.
	if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '.' || data[i-1] == '_') {
		return Finding{}, i + 1, false
	}

	// Consume digits and dots.
	j := i
	for j < len(data) && (isDigit(data[j]) || data[j] == '.') {
		j++
	}

	candidate := string(data[i:j])
	ip := net.ParseIP(candidate)
	if ip == nil || ip.To4() == nil {
		return Finding{}, j, false
	}

	// Reject if followed by a character that indicates the IP is part
	// of a larger token (dot, digit, underscore, hyphen, or letter).
	if j < len(data) && isIPv4TrailingChar(data[j]) {
		return Finding{}, j, false
	}

	return Finding{
		DetectorName: d.Name(),
		Start:        i,
		End:          j,
		Confidence:   0.8,
		RawValue:     candidate,
		Detail:       &IPAddrDetail{Version: 4},
	}, j, true
}

// isIPv4TrailingChar reports whether b indicates the IPv4 candidate is part
// of a larger token.
func isIPv4TrailingChar(b byte) bool {
	return b == '.' || isDigit(b) || b == '_' || b == '-' || isAlpha(b)
}

// tryIPv6 attempts to parse an IPv6 address starting at data[i].
// Returns the finding, the advance position, and whether a valid IPv6 was found.
func (d *IPAddr) tryIPv6(data []byte, i int) (Finding, int, bool) {
	// Word boundary: reject if preceded by alphanumeric or '_'.
	if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '_') {
		return Finding{}, i + 1, false
	}

	// Consume hex digits and colons.
	j := i
	for j < len(data) && (isHexDigit(data[j]) || data[j] == ':') {
		j++
	}

	// IPv6 must contain at least one ':'.
	if !containsColon(data[i:j]) {
		return Finding{}, j, false
	}

	// Reject if followed by alphanumeric, '_', or '-'.
	if j < len(data) && (isAlphaNum(data[j]) || data[j] == '_' || data[j] == '-') {
		return Finding{}, j, false
	}

	candidate := string(data[i:j])
	ip := net.ParseIP(candidate)
	if ip == nil || ip.To4() != nil {
		return Finding{}, j, false
	}

	return Finding{
		DetectorName: d.Name(),
		Start:        i,
		End:          j,
		Confidence:   0.8,
		RawValue:     candidate,
		Detail:       &IPAddrDetail{Version: 6},
	}, j, true
}

// containsColon reports whether data contains at least one ':'.
func containsColon(data []byte) bool {
	for _, b := range data {
		if b == ':' {
			return true
		}
	}
	return false
}

// isHexDigit reports whether b is a hexadecimal digit.
func isHexDigit(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
