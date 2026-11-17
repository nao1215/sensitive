package detect

import (
	"net"
	"slices"

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

		// Try IPv6: hex digits or ':'.
		if ascii.IsHexDigit(data[i]) || data[i] == ':' {
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
	if i > 0 && (isIdentifierByte(data[i-1]) || data[i-1] == '.') && !encodedSeparatorBefore(data, i) {
		return Finding{}, i + 1, false
	}

	// Consume digits and dots.
	j := i
	for j < len(data) && (ascii.IsDigit(data[j]) || data[j] == '.') {
		j++
	}

	candidate, ip := parseIPSentence(string(data[i:j]))
	end := i + len(candidate)
	if ip == nil || ip.To4() == nil || ip.To4()[0] == 0 || ip.IsLoopback() || versionLabel(data, i) {
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
func (d *IPAddr) tryIPv6(data []byte, i int) (Finding, int, bool) {
	// Word boundary: reject if preceded by alphanumeric or '_'.
	if i > 0 && isIdentifierByte(data[i-1]) && !encodedSeparatorBefore(data, i) {
		return Finding{}, i + 1, false
	}

	// Consume hex digits and colons.
	j := i
	for j < len(data) && (ascii.IsHexDigit(data[j]) || data[j] == ':' || data[j] == '.') {
		j++
	}

	// IPv6 must contain at least one ':'.
	if !containsColon(data[i:j]) {
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

// containsColon reports whether data contains at least one ':'.
func containsColon(data []byte) bool {
	return slices.Contains(data, ':')
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
