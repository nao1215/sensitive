package detect

// GoogleAPIKey implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindGoogleAPIKey.
type GoogleAPIKey struct{}

// NewGoogleAPIKey selects the AIza prefix and fixed API key length.
func NewGoogleAPIKey() *GoogleAPIKey {
	return &GoogleAPIKey{}
}

// Name returns "google_api_key".
func (d *GoogleAPIKey) Name() DetectorName {
	return NameGoogleAPIKey
}

// Hints returns the pre-filter substrings for [GoogleAPIKey].
func (d *GoogleAPIKey) Hints() [][]byte {
	return [][]byte{[]byte("AIza")}
}

// googleAPIKeyBodyLen is the number of characters after the "AIza" prefix.
const googleAPIKeyBodyLen = 35

// Scan returns matches in data using the rules documented on [GoogleAPIKey].
func (d *GoogleAPIKey) Scan(data []byte) []Finding {
	var findings []Finding
	const prefixLen = 4 // len("AIza")
	for i := 0; i+prefixLen+googleAPIKeyBodyLen <= len(data); {
		if !hasASCIIPrefix(data, i, "AIza") {
			i++
			continue
		}
		end := i + prefixLen + googleAPIKeyBodyLen
		if !allBytes(data, i+prefixLen, end, isTokenByte) || !credBoundary(data, i, end) {
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
