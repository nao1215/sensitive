package detect

// SlackTokenType classifies a detected Slack token by the character that follows
// the "xox" prefix. Use the SlackToken* constants for comparison with
// [SlackTokenDetail.TokenType].
type SlackTokenType string

const (
	// SlackTokenBot identifies a bot token (xoxb-).
	SlackTokenBot SlackTokenType = "bot"
	// SlackTokenUser identifies a user token (xoxp-).
	SlackTokenUser SlackTokenType = "user"
	// SlackTokenApp identifies an app-level token (xoxa-).
	SlackTokenApp SlackTokenType = "app"
	// SlackTokenOAuth identifies a legacy OAuth token (xoxo-).
	SlackTokenOAuth SlackTokenType = "oauth"
	// SlackTokenRefresh identifies a refresh token (xoxr-).
	SlackTokenRefresh SlackTokenType = "refresh"
	// SlackTokenServiceRefresh identifies a service refresh token (xoxs-).
	SlackTokenServiceRefresh SlackTokenType = "service_refresh"
)

// SlackTokenDetail holds Slack token-specific detail information.
type SlackTokenDetail struct {
	// TokenType is the token kind inferred from the fourth prefix character.
	TokenType SlackTokenType
}

// SlackToken implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindSlackToken.
type SlackToken struct{}

// NewSlackToken recognizes Slack token families and their body grammar.
func NewSlackToken() *SlackToken {
	return &SlackToken{}
}

// Name returns "slack_token".
func (d *SlackToken) Name() DetectorName {
	return NameSlackToken
}

// Hints returns the pre-filter substrings for [SlackToken].
func (d *SlackToken) Hints() [][]byte {
	return [][]byte{[]byte("xox")}
}

// slackMinBody is the minimum number of body characters after "xox<type>-".
const slackMinBody = 10

// Scan returns matches in data using the rules documented on [SlackToken].
func (d *SlackToken) Scan(data []byte) []Finding {
	var findings []Finding
	for i := 0; i+5 <= len(data); {
		kind, ok := slackTokenType(data, i)
		if !ok {
			i++
			continue
		}
		// data[i:i+4] is "xox<type>"; data[i+4] must be '-'.
		if data[i+4] != '-' {
			i++
			continue
		}
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		end, n := scanCharset(data, i+5, isSlackBodyByte)
		if n < slackMinBody || !credBoundary(data, i, end) {
			i++
			continue
		}
		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			//nolint:mnd // The detector contract documents this heuristic score.
			Confidence: 0.9,
			RawValue:   string(data[i:end]),
			Detail:     &SlackTokenDetail{TokenType: kind},
		})
		i = end
	}
	return findings
}

// slackTokenType reports the token type when data[i:i+4] is "xox" plus a known
// type character.
func slackTokenType(data []byte, i int) (SlackTokenType, bool) {
	if !hasASCIIPrefix(data, i, "xox") {
		return "", false
	}
	switch data[i+3] {
	case 'b':
		return SlackTokenBot, true
	case 'p':
		return SlackTokenUser, true
	case 'a':
		return SlackTokenApp, true
	case 'o':
		return SlackTokenOAuth, true
	case 'r':
		return SlackTokenRefresh, true
	case 's':
		return SlackTokenServiceRefresh, true
	default:
		return "", false
	}
}

// isSlackBodyByte reports whether b can appear in a Slack token body.
func isSlackBodyByte(b byte) bool {
	return isBase62(b) || b == '-'
}
