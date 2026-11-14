package detector

// GoogleAPIKeyDetail marks a Google API key finding and currently has no fields.
type GoogleAPIKeyDetail struct{}

// GoogleAPIKey detects Google API keys by format, without verifying authentication.
//
//  1. Find the AIza prefix.
//  2. Require exactly 35 following ASCII letters, digits, hyphens, or underscores, for 39 characters total.
//  3. Enforce word boundaries and score a match as 0.9.
type GoogleAPIKey struct{}

// NewGoogleAPIKey creates a new Google API key detector.
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
		if !allBytes(data, i+prefixLen, end, isGoogleKeyByte) || !credBoundary(data, i, end) {
			i++
			continue
		}
		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   0.9,
			RawValue:     string(data[i:end]),
			Detail:       &GoogleAPIKeyDetail{},
		})
		i = end
	}
	return findings
}

// allBytes reports whether every byte in data[start:end] satisfies allow.
func allBytes(data []byte, start, end int, allow func(byte) bool) bool {
	for k := start; k < end; k++ {
		if !allow(data[k]) {
			return false
		}
	}
	return true
}

// isGoogleKeyByte reports whether b can appear in a Google API key body.
func isGoogleKeyByte(b byte) bool {
	return isBase62(b) || b == '-' || b == '_'
}
