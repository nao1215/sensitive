package detect

import (
	"bytes"
	"net"
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

// IPAddr implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindIPAddr.
type IPAddr struct{}

// NewIPAddr excludes loopback addresses and IPv4 addresses whose first octet is
// zero (the this-network block, including the unspecified address), while
// retaining other valid endpoints.
func NewIPAddr() *IPAddr {
	return &IPAddr{}
}

// Name returns "ipaddr".
func (d *IPAddr) Name() DetectorName {
	return NameIPAddr
}

// Hints returns the pre-filter substrings for [IPAddr].
func (d *IPAddr) Hints() [][]byte {
	return [][]byte{
		[]byte("."),
		[]byte(":"),
	}
}

// Scan returns matches in data using the rules documented on [IPAddr].
func (d *IPAddr) Scan(data []byte) []Finding {
	var findings []Finding

	i := 0
	for i < len(data) {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if data[i] == '%' && i+3 <= len(data) && encodedSeparatorBefore(data, i+3) {
			i += 3
			continue
		}
		// Try IPv4 first if we see a digit.
		if ascii.IsDigit(data[i]) {
			if f, adv, ok := d.tryIPv4(data, i); ok {
				findings = append(findings, f)
				i = adv
				continue
			}
			// IPv4 failed — fall through to try IPv6 at the same position,
			// since decimal digits are also valid hex digits in IPv6 addresses.
		}

		// Try IPv6: hex digits or ':' that do not continue an identifier,
		// checked here so the letters a to f of a word cost no call.
		if ipv6Lead(data[i]) && leadingBoundary(data, i, isIdentifierByte) {
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
	if !leadingBoundary(data, i, isIPv4LeadingByte) {
		return Finding{}, i + 1, false
	}

	// Consume digits and dots.
	j := i
	for j < len(data) && (ascii.IsDigit(data[j]) || data[j] == '.') {
		j++
	}

	n, first, ok := dottedQuad(data[i:j])
	end := i + n
	if !ok || first == 0 || first == loopbackOctet || versionNumber(data, i) {
		return Finding{}, j, false
	}

	// Reject if followed by a character that indicates the IP is part
	// of a larger token (dot, digit, underscore, hyphen, or letter).
	if j < len(data) && isIPTokenSuffix(data, j) {
		return Finding{}, j, false
	}

	return Finding{
		DetectorName: d.Name(),
		Start:        i,
		End:          end,
		//nolint:mnd // The detector contract documents this heuristic score.
		Confidence: 0.8,
	}, j, true
}

// isIPv4LeadingByte rejects an IPv4 candidate glued to an identifier or to a
// dot, which would make it the tail of a longer dotted value.
func isIPv4LeadingByte(b byte) bool { return isIdentifierByte(b) || b == '.' }

// isIPTokenSuffix distinguishes identifiers from punctuation and IP ranges.
func isIPTokenSuffix(data []byte, at int) bool {
	b := data[at]
	if b == '-' {
		end := at + 1
		for end < len(data) && (ascii.IsHexDigit(data[end]) || data[end] == ':' || data[end] == '.') {
			end++
		}
		if _, ip := parseIPSentence(string(data[at+1 : end])); ip != nil {
			return false
		}
	}
	return ascii.IsAlphaNum(b) || ((b == '_' || b == '-') && at+1 < len(data) && ascii.IsAlphaNum(data[at+1]))
}

// tryIPv6 attempts to parse an IPv6 address starting at data[i].
// Returns the finding, the advance position, and whether a valid IPv6 was found.
// ipv6Lead reports a byte that can start an IPv6 address: a hex digit or ':'.
func ipv6Lead(b byte) bool { return ascii.IsHexDigit(b) || b == ':' }

// The caller has checked that data[i] does not continue an identifier.
func (d *IPAddr) tryIPv6(data []byte, i int) (Finding, int, bool) {
	// Consume hex digits and colons.
	j := i
	for j < len(data) && (ascii.IsHexDigit(data[j]) || data[j] == ':' || data[j] == '.') {
		j++
	}

	// The colon of a JSON key such as "level":"info" ends here, and a time
	// of day such as 12:34:56 here.
	if !ipv6Shaped(data[i:j]) {
		return Finding{}, j, false
	}

	// Reject if followed by alphanumeric, '_', or '-'.
	if j < len(data) && isIPTokenSuffix(data, j) {
		return Finding{}, j, false
	}

	candidate, ip := parseIPSentence(string(data[i:j]))
	end := i + len(candidate)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return Finding{}, j, false
	}

	return Finding{
		DetectorName: d.Name(),
		Start:        i,
		End:          end,
		//nolint:mnd // The detector contract documents this heuristic score.
		Confidence: 0.8,
	}, j, true
}

const (
	// minIPv6Colons is the fewest colons of an IPv6 address, as in ::1.
	minIPv6Colons = 2
	// loopbackOctet starts every IPv4 loopback address, 127.0.0.0/8.
	loopbackOctet = 127
)

// ipv6Shaped reports whether a run of hex digits, colons and dots can hold an
// address before its trailing punctuation: every form has two colons, eight
// groups need seven, six groups and an IPv4 tail need six, and a shorter form
// needs "::". A run whose only colons trail it may still hold an IPv4 address.
func ipv6Shaped(run []byte) bool {
	const minFullColons = 6
	colons := bytes.Count(run, []byte{':'})
	if colons < minIPv6Colons {
		return false
	}
	if colons >= minFullColons || bytes.Contains(run, []byte("::")) {
		return true
	}
	end := len(run)
	for end > 0 && (run[end-1] == '.' || run[end-1] == ':') {
		end--
	}
	return bytes.IndexByte(run[:end], ':') < 0
}

// dottedQuad reads four decimal octets from a run of digits and dots, as in
// 10.0.0.1 or 10.0.0.1. at the end of a sentence, and returns the length
// without trailing dots and the first octet. Octets may carry leading zeros
// (192.168.001.010), as some firewall and appliance logs print them; a log
// reader still sees the address. Timestamps, ports and counters fail without
// allocating.
func dottedQuad(run []byte) (n, first int, ok bool) {
	n = len(run)
	for n > 0 && run[n-1] == '.' {
		n--
	}
	const octets, maxOctetLen, maxOctet, base = 4, 3, 255, 10
	parts, value, digits := 0, 0, 0
	for k := 0; k <= n; k++ {
		if k < n && run[k] != '.' {
			value = value*base + int(run[k]-'0')
			digits++
			if digits > maxOctetLen {
				return 0, 0, false
			}
			continue
		}
		if digits == 0 || value > maxOctet || parts == octets {
			return 0, 0, false
		}
		if parts == 0 {
			first = value
		}
		parts++
		value, digits = 0, 0
	}
	return n, first, parts == octets
}

// versionNumber reports an address-shaped number that a label or a product
// name before start marks as a version.
func versionNumber(data []byte, start int) bool {
	return versionLabel(data, start) || productVersion(data, start)
}

// productVersion reports an address-shaped number written as a product
// version, as in agent/5.1.2.3 of a User-Agent: a word that starts with a
// letter at a field boundary and ends with the slash before start. Words that
// name an address, such as ip/ or peer/, keep the address.
func productVersion(data []byte, start int) bool {
	if start == 0 || data[start-1] != '/' {
		return false
	}
	begin := start - 1
	for begin > 0 && (ascii.IsAlphaNum(data[begin-1]) || data[begin-1] == '-' || data[begin-1] == '_') {
		begin--
	}
	if begin == start-1 || !ascii.IsAlpha(data[begin]) || (begin > 0 && !strings.ContainsRune(" \t\"'(", rune(data[begin-1]))) {
		return false
	}
	return !labelIs(data[begin:start-1], "ip", "ipv4", "host", "addr", "address", "src", "dst", "peer", "client", "server", "remote", "proxy", "from", "to")
}

func versionLabel(data []byte, start int) bool {
	_, word := previousLabelWord(labelPrefix(data, start))
	return labelIs(word, "version", "v", "ver", "build", "release")
}

// parseIPSentence keeps the longest valid address before sentence punctuation.
// At most two terminal colons can belong to an IPv6 address; bounded retries
// avoid quadratic parsing of a long run of dots or colons.
func parseIPSentence(candidate string) (string, net.IP) {
	if ip := net.ParseIP(candidate); ip != nil {
		return candidate, ip
	}
	end := len(candidate)
	for end > 0 && (candidate[end-1] == '.' || candidate[end-1] == ':') {
		end--
	}
	if end == len(candidate) {
		return candidate, nil
	}
	colons := end
	for colons < len(candidate) && colons < end+2 && candidate[colons] == ':' {
		colons++
	}
	for stop := colons; stop >= end; stop-- {
		if ip := net.ParseIP(candidate[:stop]); ip != nil {
			return candidate[:stop], ip
		}
	}
	return candidate, nil
}
