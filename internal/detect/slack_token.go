package detect

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
		if !credStartBoundary(data, i) {
			i++
			continue
		}
		if !slackTokenPrefix(data, i) {
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
		})
		i = end
	}
	return findings
}

// slackTokenPrefix reports whether data[i:i+4] is "xox" plus a known type character.
func slackTokenPrefix(data []byte, i int) bool {
	if !hasASCIIPrefix(data, i, "xox") {
		return false
	}
	switch data[i+3] {
	case 'b':
		return true
	case 'p':
		return true
	case 'a':
		return true
	case 'o':
		return true
	case 'r':
		return true
	case 's':
		return true
	default:
		return false
	}
}

// isSlackBodyByte reports whether b can appear in a Slack token body.
func isSlackBodyByte(b byte) bool {
	return isAlphaNum(b) || b == '-'
}
