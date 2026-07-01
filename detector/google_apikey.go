package detector

// GoogleAPIKeyDetail holds Google API key-specific detail information.
// It is currently empty; the type exists so the finding carries a typed,
// forward-compatible Detail like the other detectors.
type GoogleAPIKeyDetail struct{}

// GoogleAPIKey detects Google API keys in text.
//
// Google API keys are 39-character strings that start with the fixed "AIza"
// prefix followed by exactly 35 characters of A-Z, a-z, 0-9, '-' or '_'.
//
// Detection logic:
//  1. Scan for the "AIza" prefix.
//  2. Validate that the next 35 characters are in the allowed set.
//  3. Enforce word boundaries so a key embedded in a longer identifier is not
//     matched.
//
// Confidence: 0.9 — the "AIza" prefix with the fixed length is characteristic of
// Google API keys.
type GoogleAPIKey struct{}

// NewGoogleAPIKey creates a new Google API key detector.
func NewGoogleAPIKey() *GoogleAPIKey {
	return &GoogleAPIKey{}
}

// Name returns "google_api_key".
func (d *GoogleAPIKey) Name() DetectorName {
	return NameGoogleAPIKey
}

// Hints returns byte sequences for pre-filtering. Every Google API key begins
// with "AIza", so it is an exhaustive hint.
func (d *GoogleAPIKey) Hints() [][]byte {
	return [][]byte{[]byte("AIza")}
}

// googleAPIKeyBodyLen is the number of characters after the "AIza" prefix.
const googleAPIKeyBodyLen = 35

// Scan examines data for Google API keys and returns findings.
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
