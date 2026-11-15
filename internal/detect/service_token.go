package detect

import (
	"bytes"
	"strings"
)

// ServiceToken finds documented provider prefixes with a conservative minimum
// body length of 16, at confidence 0.95. Prefixes are not authentication checks;
// vendor lengths can change. SendGrid requires its two 22/43-byte URL-safe parts.
// Slack webhooks expose only the path credential, retaining the host.
type ServiceToken struct{}

// Name returns the service token family.
func (*ServiceToken) Name() DetectorName { return "service_token" }

// Hints returns exhaustive provider prefixes.
func (*ServiceToken) Hints() [][]byte {
	return [][]byte{[]byte("sk-"), []byte("sk_live_"), []byte("rk_live_"), []byte("whsec_"), []byte("glpat-"), []byte("npm_"), []byte("pypi-"), []byte("GOCSPX-"), []byte("SG."), []byte("hooks.slack.com/services/"), []byte("hooks.slack-gov.com/services/")}
}

// Scan finds provider credentials without contacting any service.
func (d *ServiceToken) Scan(data []byte) []Finding {
	var out []Finding
	for i := 0; i < len(data); i++ {
		if i > 0 && (isBase62(data[i-1]) || data[i-1] == '_') {
			continue
		}
		end := serviceTokenEnd(data, i)
		if end <= i {
			continue
		}
		start := i
		if bytes.HasPrefix(data[i:], []byte("https://hooks.slack")) {
			marker := bytes.Index(data[i:end], []byte("/services/"))
			if marker < 0 {
				continue
			}
			start = i + marker + len("/services/")
		}
		//nolint:mnd // Prefix-based candidates use the documented heuristic score.
		out = append(out, Finding{DetectorName: d.Name(), Start: start, End: end, Confidence: 0.95, RawValue: string(data[start:end])})
		i = end - 1
	}
	return out
}

func serviceTokenEnd(data []byte, start int) int {
	for _, prefix := range []string{"sk-proj-", "sk-svcacct-", "sk-ant-api03-", "sk-ant-admin01-", "sk_live_", "rk_live_", "whsec_", "glpat-", "npm_", "pypi-", "GOCSPX-"} {
		if !bytes.HasPrefix(data[start:], []byte(prefix)) {
			continue
		}
		end := start + len(prefix)
		for end < len(data) && tokenByte(data[end]) {
			end++
		}
		const minBody = 16
		if end-start-len(prefix) >= minBody {
			return end
		}
		return start
	}
	if bytes.HasPrefix(data[start:], []byte("SG.")) {
		const firstLen, secondLen = 22, 43
		middle := start + len("SG.") + firstLen
		end := middle + 1 + secondLen
		if end <= len(data) && data[middle] == '.' && allTokenBytes(data[start+len("SG."):middle]) && allTokenBytes(data[middle+1:end]) && (end == len(data) || !tokenByte(data[end])) {
			return end
		}
	}
	for _, prefix := range []string{"https://hooks.slack.com/services/", "https://hooks.slack-gov.com/services/"} {
		if !bytes.HasPrefix(data[start:], []byte(prefix)) {
			continue
		}
		end := start + len(prefix)
		for end < len(data) && (tokenByte(data[end]) || data[end] == '/') {
			end++
		}
		parts := strings.Split(string(data[start+len(prefix):end]), "/")
		const minWebhookSecret = 16
		if len(parts) == 3 && len(parts[0]) > 1 && len(parts[1]) > 1 && len(parts[2]) >= minWebhookSecret {
			return end
		}
	}
	return start
}

func tokenByte(b byte) bool { return isBase62(b) || b == '_' || b == '-' }
func allTokenBytes(data []byte) bool {
	for _, b := range data {
		if !tokenByte(b) {
			return false
		}
	}
	return true
}
