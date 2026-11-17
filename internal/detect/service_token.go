package detect

import (
	"bytes"
	"strings"
)

// ServiceToken implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken.
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
		if i > 0 && isIdentifierByte(data[i-1]) {
			continue
		}
		end := serviceTokenEnd(data, i)
		if end <= i {
			continue
		}
		start := i
		if bytes.HasPrefix(data[i:], []byte("https://hooks.slack")) {
			marker := bytes.Index(data[i:end], []byte("/services/"))
			// serviceTokenEnd accepted a complete /services/ prefix.
			start = i + marker + len("/services/")
		}
		//nolint:mnd // Prefix-based candidates use the documented heuristic score.
		out = append(out, Finding{DetectorName: d.Name(), Start: start, End: end, Confidence: 0.95})
		i = end - 1
	}
	return out
}

func serviceTokenEnd(data []byte, start int) int {
	if end, ok := prefixedServiceTokenEnd(data, start); ok {
		return end
	}
	if end, ok := sendGridKeyEnd(data, start); ok {
		return end
	}
	return slackWebhookEnd(data, start)
}

// prefixedServiceTokenEnd owns the fixed-prefix tokens: once a prefix matches,
// it decides the result alone, returning start when the body is too short.
func prefixedServiceTokenEnd(data []byte, start int) (int, bool) {
	for _, prefix := range []string{"sk-proj-", "sk-svcacct-", "sk-ant-api03-", "sk-ant-admin01-", "sk_live_", "rk_live_", "whsec_", "glpat-", "npm_", "pypi-", "GOCSPX-"} {
		if !bytes.HasPrefix(data[start:], []byte(prefix)) {
			continue
		}
		end := start + len(prefix)
		for end < len(data) && isTokenByte(data[end]) {
			end++
		}
		const minBody = 16
		if end-start-len(prefix) >= minBody {
			return end, true
		}
		return start, true
	}
	return start, false
}

// sendGridKeyEnd matches the fixed SG.<22>.<43> SendGrid key layout followed
// by a token boundary.
func sendGridKeyEnd(data []byte, start int) (int, bool) {
	if !bytes.HasPrefix(data[start:], []byte("SG.")) {
		return start, false
	}
	const firstLen, secondLen = 22, 43
	middle := start + len("SG.") + firstLen
	end := middle + 1 + secondLen
	if end <= len(data) && data[middle] == '.' && allBytes(data, start+len("SG."), middle, isTokenByte) && allBytes(data, middle+1, end, isTokenByte) && (end == len(data) || !isTokenByte(data[end])) {
		return end, true
	}
	return start, false
}

// slackWebhookEnd matches a Slack webhook URL with three path parts and a
// long enough secret, returning start otherwise.
func slackWebhookEnd(data []byte, start int) int {
	for _, prefix := range []string{"https://hooks.slack.com/services/", "https://hooks.slack-gov.com/services/"} {
		if !bytes.HasPrefix(data[start:], []byte(prefix)) {
			continue
		}
		end := start + len(prefix)
		for end < len(data) && (isTokenByte(data[end]) || data[end] == '/') {
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
