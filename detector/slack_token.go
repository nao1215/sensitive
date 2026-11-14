package detector

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

// SlackToken detects Slack API tokens by format, without verifying authentication.
//
//  1. Find xox followed by b, p, a, o, r, or s and a hyphen; [SlackTokenType] names these families.
//  2. Consume ASCII letters, digits, and hyphens, requiring at least ten body characters.
//  3. Enforce a leading word boundary and score a match as 0.9.
type SlackToken struct{}

// NewSlackToken creates a new Slack token detector.
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
		end, n := scanCharset(data, i+5, isSlackBodyByte)
		if n < slackMinBody || !credBoundary(data, i, end) {
			i++
			continue
		}
		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   0.9,
			RawValue:     string(data[i:end]),
			Detail:       &SlackTokenDetail{TokenType: kind},
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
