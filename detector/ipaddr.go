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
		// Try IPv4: look for a digit that could start an IP address.
		if isDigit(data[i]) {
			// Check that it's not part of a longer word or identifier.
			if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '.' || data[i-1] == '_') {
				i++
				continue
			}

			start := i
			j := i
			for j < len(data) && (isDigit(data[j]) || data[j] == '.') {
				j++
			}

			candidate := string(data[start:j])
			ip := net.ParseIP(candidate)
			if ip != nil && ip.To4() != nil {
				// Skip if followed by a character that indicates the IP is part
				// of a larger token (dot, digit, underscore, hyphen, or letter).
				if j < len(data) && (data[j] == '.' || isDigit(data[j]) || data[j] == '_' || data[j] == '-' || isAlpha(data[j])) {
					i = j
					continue
				}

				findings = append(findings, Finding{
					DetectorName: d.Name(),
					Start:        start,
					End:          j,
					Confidence:   0.8,
					RawValue:     candidate,
					Detail:       &IPAddrDetail{Version: 4},
				})
				i = j
				continue
			}
		}

		// Try IPv6: look for hex digits followed by ':'.
		if isHexDigit(data[i]) || data[i] == ':' {
			if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '_') {
				i++
				continue
			}

			start := i
			j := i
			for j < len(data) && (isHexDigit(data[j]) || data[j] == ':') {
				j++
			}

			// IPv6 must contain at least one ':'.
			hasColon := false
			for k := start; k < j; k++ {
				if data[k] == ':' {
					hasColon = true
					break
				}
			}
			if hasColon {
				// Skip if followed by an alphanumeric character (not a
				// standalone address). The consumption loop already ate
				// all hex digits and colons, so a trailing letter (g-z,
				// G-Z) means the candidate is part of a longer token
				// (e.g., a log identifier like "2001:db8::1xyz").
				if j < len(data) && (isAlphaNum(data[j]) || data[j] == '_' || data[j] == '-') {
					i = j
					continue
				}

				candidate := string(data[start:j])
				ip := net.ParseIP(candidate)
				if ip != nil && ip.To4() == nil {
					findings = append(findings, Finding{
						DetectorName: d.Name(),
						Start:        start,
						End:          j,
						Confidence:   0.8,
						RawValue:     candidate,
						Detail:       &IPAddrDetail{Version: 6},
					})
					i = j
					continue
				}
			}
		}

		i++
	}

	return findings
}

// isHexDigit reports whether b is a hexadecimal digit.
func isHexDigit(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
