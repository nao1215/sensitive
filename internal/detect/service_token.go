package detect

import (
	"bytes"
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

// ServiceToken implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken.
type ServiceToken struct {
	index *providerIndex
}

// NewServiceToken compiles the provider prefix table.
func NewServiceToken() *ServiceToken {
	return &ServiceToken{index: newProviderIndex()}
}

// nameServiceToken is the provider token detector, which has no exported name.
const nameServiceToken DetectorName = "service_token"

// Name returns the service token family.
func (*ServiceToken) Name() DetectorName { return nameServiceToken }

// Hints returns every table prefix plus a substring that each special layout
// contains, so the list is exhaustive by construction.
func (*ServiceToken) Hints() [][]byte {
	special := []string{"hooks.slack.com/", "hooks.slack-gov.com/", "webhook.office.com/webhookb2/", "/api/webhooks/", ".sentry.io/", ".atlasv1.", "Q~", ":A", "_mmk", "-us", "|"}
	seen := map[string]bool{}
	var out [][]byte
	for _, layout := range providerLayouts() {
		if !seen[layout.prefix] {
			seen[layout.prefix] = true
			out = append(out, []byte(layout.prefix))
		}
	}
	for _, hint := range special {
		out = append(out, []byte(hint))
	}
	return out
}

// Scan finds provider credentials without contacting any service.
func (d *ServiceToken) Scan(data []byte) []Finding {
	index := d.index
	if index == nil {
		index = newProviderIndex()
	}
	var out []Finding
	present := presentLayouts(data)
	for i := 0; i < len(data); i++ {
		if i > 0 && isIdentifierByte(data[i-1]) && !telegramBotPath(data, i) {
			continue
		}
		start, end := serviceTokenSpan(index, data, i, present)
		if end <= start {
			continue
		}
		//nolint:mnd // Prefix-based candidates use the documented heuristic score.
		out = append(out, Finding{DetectorName: d.Name(), Start: start, End: end, Confidence: 0.95})
		i = end - 1
	}
	return out
}

// serviceTokenSpan returns the credential span that begins its layout at
// position i; webhook URLs report only their secret path. present holds the
// layouts whose marker data contains, from presentLayouts.
func serviceTokenSpan(index *providerIndex, data []byte, i int, present uint16) (start, end int) {
	if end, ok := index.match(data, i); ok {
		return i, end
	}
	specials := specialTokenEnds()
	for k, layout := range specials {
		if present&(1<<k) == 0 {
			continue
		}
		if end, ok := layout(data, i); ok {
			return i, end
		}
	}
	for k, layout := range secretPathSpans() {
		if present&(1<<(len(specials)+k)) == 0 {
			continue
		}
		if start, end, ok := layout(data, i); ok {
			return start, end
		}
	}
	return i, i
}

// The layouts that specialTokenEnds and secretPathSpans return, which
// layoutMarkers lists in that order.
const specialLayouts, pathLayouts = 6, 4

// layoutMarkers returns a substring that every match of each layout contains,
// in the order of specialTokenEnds and then secretPathSpans.
func layoutMarkers() [specialLayouts + pathLayouts]string {
	return [...]string{".atlasv1.", "Q~", ":A", "_mmk", "-us", "|", "hooks.slack", ".webhook.office.com/webhookb2/", "/api/webhooks/", ".sentry.io/"}
}

// presentLayouts returns one bit per layout whose marker occurs in data, so
// a line without any marker tries none of them at each position.
func presentLayouts(data []byte) uint16 {
	var present uint16
	for k, marker := range layoutMarkers() {
		if bytes.Contains(data, []byte(marker)) {
			present |= 1 << k
		}
	}
	return present
}

// specialTokenEnds returns the layouts the prefix table cannot express, each
// reporting the end of a token that starts at the given position.
func specialTokenEnds() [specialLayouts]func([]byte, int) (int, bool) {
	return [...]func([]byte, int) (int, bool){terraformTokenEnd, azureClientSecretEnd, telegramBotTokenEnd, maxMindLicenseKeyEnd, mailchimpKeyEnd, facebookAppTokenEnd}
}

// secretPathSpans returns the URL layouts that start at the given position and
// report only the secret part of the URL.
func secretPathSpans() [pathLayouts]func([]byte, int) (int, int, bool) {
	return [...]func([]byte, int) (int, int, bool){slackWebhookSpan, teamsWebhookSpan, discordWebhookSpan, sentryDSNSpan}
}

// terraformTokenEnd matches a Terraform Cloud token: 14 ASCII letters or
// digits, the literal .atlasv1. and 60 to 70 token bytes or '='.
func terraformTokenEnd(data []byte, start int) (int, bool) {
	const idLen, minBody, maxBody = 14, 60, 70
	marker := start + idLen
	if marker+len(".atlasv1.") > len(data) || !hasASCIIPrefix(data, marker, ".atlasv1.") || !allBytes(data, start, marker, ascii.IsAlphaNum) {
		return start, false
	}
	body := marker + len(".atlasv1.")
	end := body
	for end < len(data) && isTokenOrEquals(data[end]) {
		end++
	}
	if end-body < minBody || end-body > maxBody {
		return start, false
	}
	return end, true
}

// azureClientSecretEnd matches the Microsoft Entra client secret layout:
// three bytes, a digit, the literal Q~ and 31 to 34 more bytes, all drawn
// from ASCII letters, digits, _, ~ and dots, with hyphens allowed after Q~.
func azureClientSecretEnd(data []byte, start int) (int, bool) {
	const headLen, minTail, maxTail = 3, 31, 34
	marker := start + headLen + 1
	if marker > len(data) || !hasASCIIPrefix(data, marker, "Q~") || !ascii.IsDigit(data[marker-1]) || !allBytes(data, start, start+headLen, isAzureSecretByte) {
		return start, false
	}
	tail := marker + len("Q~")
	end := tail
	for end < len(data) && (isAzureSecretByte(data[end]) || data[end] == '-') {
		end++
	}
	for end > tail && data[end-1] == '.' {
		end--
	}
	if end-tail < minTail || end-tail > maxTail {
		return start, false
	}
	return end, true
}

func isAzureSecretByte(b byte) bool { return ascii.IsAlphaNum(b) || b == '_' || b == '~' || b == '.' }

// telegramBotTokenEnd matches a Telegram bot token: a 5 to 16 digit bot ID,
// a colon and a 35-byte secret that starts with A.
func telegramBotTokenEnd(data []byte, start int) (int, bool) {
	const minID, maxID, secretLen = 5, 16, 35
	colon := start
	for colon < len(data) && ascii.IsDigit(data[colon]) {
		colon++
	}
	if colon-start < minID || colon-start > maxID || colon+1+secretLen > len(data) || data[colon] != ':' || data[colon+1] != 'A' {
		return start, false
	}
	end := colon + 1 + secretLen
	if !allBytes(data, colon+1, end, isTokenByte) || (end < len(data) && isTokenByte(data[end])) {
		return start, false
	}
	return end, true
}

// telegramBotPath lets a bot token start right after /bot in Bot API URLs.
func telegramBotPath(data []byte, i int) bool {
	return i >= 4 && ascii.IsDigit(data[i]) && string(data[i-4:i]) == "/bot"
}

// slackWebhookSpan matches Slack incoming webhook, workflow and trigger URLs
// with an optional http or https scheme and reports only the path after the
// webhook kind.
func slackWebhookSpan(data []byte, start int) (body, end int, ok bool) {
	pos := start
	for _, scheme := range []string{"https://", "http://"} {
		if hasASCIIPrefix(data, pos, scheme) {
			pos += len(scheme)
			break
		}
	}
	body, incoming, found := slackWebhookBody(data, pos)
	if !found {
		return start, start, false
	}
	end = body
	for end < len(data) && (isTokenByte(data[end]) || data[end] == '/') {
		end++
	}
	return body, end, slackWebhookPath(string(data[body:end]), incoming)
}

// slackWebhookBody returns where the path after a Slack webhook host and kind
// starts and whether the kind is an incoming webhook.
func slackWebhookBody(data []byte, pos int) (body int, incoming, ok bool) {
	for _, host := range []string{"hooks.slack.com/", "hooks.slack-gov.com/"} {
		if !hasASCIIPrefix(data, pos, host) {
			continue
		}
		for _, kind := range []string{"services/", "workflows/", "triggers/"} {
			if hasASCIIPrefix(data, pos+len(host), kind) {
				return pos + len(host) + len(kind), kind == "services/", true
			}
		}
	}
	return pos, false, false
}

// slackWebhookPath checks the slash-separated path: incoming webhooks need
// three parts and workflow or trigger URLs three or four; every part needs two
// bytes and the last one, the secret, needs 16.
func slackWebhookPath(path string, incoming bool) bool {
	const incomingParts, workflowParts, minPart, minWebhookSecret = 3, 4, 2, 16
	parts := strings.Split(path, "/")
	if len(parts) != incomingParts && (incoming || len(parts) != workflowParts) {
		return false
	}
	for _, part := range parts[:len(parts)-1] {
		if len(part) < minPart {
			return false
		}
	}
	return len(parts[len(parts)-1]) >= minWebhookSecret
}

// teamsWebhookSpan matches a Microsoft Teams incoming webhook URL and reports
// the path after /webhookb2/, which carries the tenant and secret parts.
func teamsWebhookSpan(data []byte, start int) (body, end int, ok bool) {
	if !hasASCIIPrefix(data, start, "https://") {
		return start, start, false
	}
	host := start + len("https://")
	sub := host
	for sub < len(data) && ascii.IsAlphaNum(data[sub]) {
		sub++
	}
	if sub == host || !hasASCIIPrefix(data, sub, ".webhook.office.com/webhookb2/") {
		return start, start, false
	}
	body = sub + len(".webhook.office.com/webhookb2/")
	end = body
	for end < len(data) && (isTokenByte(data[end]) || data[end] == '/' || data[end] == '@') {
		end++
	}
	const minPath = 64
	if end-body < minPath || !bytes.Contains(data[body:end], []byte("/IncomingWebhook/")) {
		return start, start, false
	}
	return body, end, true
}

// discordWebhookSpan matches a Discord webhook URL on discord.com,
// discordapp.com or their ptb and canary hosts, and reports the path after
// /api/webhooks/: a 17 to 20 digit ID, a slash and a 60 to 80 byte token.
func discordWebhookSpan(data []byte, start int) (body, end int, ok bool) {
	body, ok = discordWebhookBody(data, start)
	if !ok {
		return start, start, false
	}
	const minID, maxID, minToken, maxToken = 17, 20, 60, 80
	slash := body
	for slash < len(data) && ascii.IsDigit(data[slash]) {
		slash++
	}
	if slash-body < minID || slash-body > maxID || slash >= len(data) || data[slash] != '/' {
		return start, start, false
	}
	end = slash + 1
	for end < len(data) && isTokenByte(data[end]) {
		end++
	}
	if token := end - slash - 1; token < minToken || token > maxToken {
		return start, start, false
	}
	return body, end, true
}

// discordWebhookBody returns where the path after https://[ptb.|canary.]
// discord.com/api/webhooks/ or discordapp.com/api/webhooks/ starts.
func discordWebhookBody(data []byte, start int) (int, bool) {
	if !hasASCIIPrefix(data, start, "https://") {
		return start, false
	}
	host := start + len("https://")
	for _, sub := range []string{"ptb.", "canary."} {
		if hasASCIIPrefix(data, host, sub) {
			host += len(sub)
			break
		}
	}
	for _, path := range []string{"discord.com/api/webhooks/", "discordapp.com/api/webhooks/"} {
		if hasASCIIPrefix(data, host, path) {
			return host + len(path), true
		}
	}
	return start, false
}

// sentryDSNSpan matches a Sentry DSN for the hosted service,
// https://<32 hex>@o<org>.ingest[.<region>].sentry.io/<project>, and reports
// the 32-digit key. Self-hosted DSNs use arbitrary hosts and are left to the
// URL credential rules.
func sentryDSNSpan(data []byte, start int) (body, end int, ok bool) {
	if !hasASCIIPrefix(data, start, "https://") {
		return start, start, false
	}
	const keyLen = 32
	body = start + len("https://")
	end = body + keyLen
	if end >= len(data) || data[end] != '@' || !allBytes(data, body, end, ascii.IsHexDigit) {
		return start, start, false
	}
	host := end + 1
	slash := host
	for slash < len(data) && (ascii.IsAlphaNum(data[slash]) || data[slash] == '.' || data[slash] == '-') {
		slash++
	}
	name := string(data[host:slash])
	if slash >= len(data) || data[slash] != '/' || !strings.HasSuffix(name, ".sentry.io") || !strings.Contains(name, ".ingest.") {
		return start, start, false
	}
	return body, end, true
}

// maxMindLicenseKeyEnd matches a MaxMind license key: 6 and 29 ASCII letters
// or digits joined by an underscore and followed by the literal _mmk.
func maxMindLicenseKeyEnd(data []byte, start int) (int, bool) {
	const headLen, bodyLen = 6, 29
	sep := start + headLen
	suffix := sep + 1 + bodyLen
	end := suffix + len("_mmk")
	if end > len(data) || data[sep] != '_' || !hasASCIIPrefix(data, suffix, "_mmk") || !allBytes(data, start, sep, ascii.IsAlphaNum) || !allBytes(data, sep+1, suffix, ascii.IsAlphaNum) || (end < len(data) && isTokenByte(data[end])) {
		return start, false
	}
	return end, true
}

// mailchimpKeyEnd matches a Mailchimp API key: 32 lower-case hexadecimal
// digits, the literal -us and a two-digit data center number.
func mailchimpKeyEnd(data []byte, start int) (int, bool) {
	const hexLen, dcLen = 32, 2
	dash := start + hexLen
	end := dash + len("-us") + dcLen
	if end > len(data) || !hasASCIIPrefix(data, dash, "-us") || !allBytes(data, start, dash, isLowerHexOrDigit) || !allBytes(data, end-dcLen, end, ascii.IsDigit) || (end < len(data) && isTokenByte(data[end])) {
		return start, false
	}
	return end, true
}

// facebookAppTokenEnd matches a Facebook app access token: a 15 or 16 digit
// app ID, a pipe or its %7C escape and a 27 to 40 byte app secret.
func facebookAppTokenEnd(data []byte, start int) (int, bool) {
	const minID, maxID, minSecret, maxSecret = 15, 16, 27, 40
	sep := start
	for sep < len(data) && ascii.IsDigit(data[sep]) {
		sep++
	}
	if sep-start < minID || sep-start > maxID || sep >= len(data) || data[sep] != '|' {
		return start, false
	}
	body := sep + 1
	end := body
	for end < len(data) && isTokenByte(data[end]) {
		end++
	}
	if end-body < minSecret || end-body > maxSecret {
		return start, false
	}
	return end, true
}
