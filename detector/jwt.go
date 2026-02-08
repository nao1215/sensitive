package detector

import (
	"encoding/base64"
	"encoding/json"
)

// decodeJWTHeader attempts to base64-decode and JSON-parse the JWT header.
// Returns the algorithm string and a confidence boost (0.0 to 0.3).
func decodeJWTHeader(headerPart []byte) (algorithm string, boost float64) {
	headerJSON, err := base64.RawURLEncoding.DecodeString(string(headerPart))
	if err != nil {
		return "", 0
	}
	var header map[string]any
	if json.Unmarshal(headerJSON, &header) != nil {
		return "", 0
	}
	boost = 0.2
	alg, ok := header["alg"]
	if !ok {
		return "", boost
	}
	boost += 0.1
	if s, ok := alg.(string); ok {
		return s, boost
	}
	return "", boost
}

// JWTDetail holds JWT-specific detail information.
type JWTDetail struct {
	// Algorithm is the signing algorithm from the JWT header (e.g., "HS256", "RS256").
	// Empty if the header could not be decoded.
	Algorithm string
}

// JWT detects JSON Web Tokens in text.
//
// JWT detection relies on the characteristic "eyJ" prefix, which is the
// base64url encoding of '{"' — the start of every JSON object. The detector
// then validates the three-part structure (header.payload.signature) and
// optionally decodes the header to check for valid JSON with an "alg" key.
//
// Unsigned JWTs (alg:"none") are also detected. These tokens have an empty
// signature part (e.g., "header.payload.") and are reported with lower base
// confidence (0.5 instead of 0.7) because they may also indicate a malformed
// string. Detecting unsigned JWTs is important because alg:none is a known
// attack vector (CVE-2015-9235 and related).
//
// Confidence is calculated as:
//   - Signed JWT ("eyJ" prefix + 2 dots + non-empty signature): base 0.7
//   - Unsigned JWT ("eyJ" prefix + 2 dots + empty signature): base 0.5
//   - + Header decodes to valid JSON: +0.2
//   - + Header contains "alg" key: +0.1
type JWT struct{}

// NewJWT creates a new JWT detector.
func NewJWT() *JWT {
	return &JWT{}
}

// Name returns "jwt".
func (d *JWT) Name() DetectorName {
	return NameJWT
}

// Hints returns byte sequences for pre-filtering.
// All JWTs start with "eyJ" (base64url encoding of '{"'), making this
// a highly specific hint that efficiently eliminates non-matching input.
func (d *JWT) Hints() [][]byte {
	return [][]byte{
		[]byte("eyJ"),
	}
}

// Scan examines data for JWT tokens and returns findings.
func (d *JWT) Scan(data []byte) []Finding {
	var findings []Finding

	i := 0
	for i < len(data)-2 {
		end, parts, ok := extractJWTToken(data, i)
		if !ok {
			i = end
			continue
		}

		confidence := 0.7
		if len(parts[2]) == 0 {
			// Unsigned JWT (alg:none or malformed). These tokens have an empty
			// signature part (e.g., "header.payload."). We intentionally detect
			// them because alg:none is a known attack vector (CVE-2015-9235),
			// but use lower base confidence since they may also be malformed strings.
			confidence = 0.5
		}
		algorithm, boost := decodeJWTHeader(parts[0])
		confidence += boost

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   confidence,
			RawValue:     string(data[i:end]),
			Detail:       &JWTDetail{Algorithm: algorithm},
		})

		i = end
	}

	return findings
}

// extractJWTToken checks whether data[i:] starts with a valid JWT token.
// Returns the end position, the three token parts, and whether extraction succeeded.
// On failure, end is the position to resume scanning from.
func extractJWTToken(data []byte, i int) (end int, parts [][]byte, ok bool) {
	// Must start with "eyJ" prefix.
	if data[i] != 'e' || data[i+1] != 'y' || data[i+2] != 'J' {
		return i + 1, nil, false
	}

	// Leading boundary: reject if preceded by a base64url character
	// (alphanumeric, '-', or '_'). This prevents false positives when
	// "eyJ" appears inside a longer base64url-encoded string.
	if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '-' || data[i-1] == '_') {
		return i + 1, nil, false
	}

	// Extract the token: base64url chars + dots.
	j := i
	dotCount := 0
	for j < len(data) && isJWTChar(data[j]) {
		if data[j] == '.' {
			dotCount++
		}
		j++
	}

	// JWT must have exactly 2 dots (header.payload.signature).
	if dotCount != 2 {
		return j, nil, false
	}

	// Split into parts and validate.
	parts = splitJWT(data[i:j])
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return j, nil, false
	}

	return j, parts, true
}

// isJWTChar reports whether b is a valid character in a JWT token.
// JWT uses base64url encoding (A-Z, a-z, 0-9, '-', '_') with '.' as separator.
func isJWTChar(b byte) bool {
	return isAlphaNum(b) || b == '-' || b == '_' || b == '.'
}

// splitJWT splits a JWT token into its three parts at the '.' separators.
func splitJWT(data []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '.' {
			parts = append(parts, data[start:i])
			start = i + 1
		}
	}
	return parts
}
