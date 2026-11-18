package detect

import (
	"encoding/base64"
	"encoding/json"
)

// decodeJWTHeader attempts to base64-decode and JSON-parse the JWT header.
// Returns a confidence boost in integer tenths (0 to 3).
func decodeJWTHeader(headerPart []byte) (boost int) {
	headerJSON, err := base64.RawURLEncoding.DecodeString(string(headerPart))
	if err != nil {
		return 0
	}
	var header map[string]any
	if json.Unmarshal(headerJSON, &header) != nil {
		return 0
	}
	const objectPoints, algorithmPoints = 2, 1
	boost = objectPoints
	_, ok := header["alg"]
	if !ok {
		return boost
	}
	boost += algorithmPoints
	return boost
}

// JWT implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindJWT.
type JWT struct{}

// NewJWT checks three base64url segments and the decoded header.
func NewJWT() *JWT {
	return &JWT{}
}

// Name returns "jwt".
func (d *JWT) Name() DetectorName {
	return NameJWT
}

// Hints returns the pre-filter substrings for [JWT].
func (d *JWT) Hints() [][]byte {
	return [][]byte{
		[]byte("eyJ"),
	}
}

// Scan returns matches in data using the rules documented on [JWT].
func (d *JWT) Scan(data []byte) []Finding {
	var findings []Finding

	i := 0
	for i < len(data)-2 {
		end, parts, ok := extractJWTToken(data, i)
		if !ok {
			i = end
			continue
		}

		const signedPoints, unsignedPoints, scoreScale = 7, 5, 10
		points := signedPoints
		if len(parts[2]) == 0 {
			// Unsigned JWT (alg:none or malformed). These tokens have an empty
			// signature part (e.g., "header.payload."). We intentionally detect
			// them because alg:none is a known attack vector (CVE-2015-9235),
			// but use lower base confidence since they may also be malformed strings.
			points = unsignedPoints
		}
		boost := decodeJWTHeader(parts[0])
		points += boost

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   float64(points) / scoreScale,
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
	if !leadingBoundary(data, i, isTokenByte) {
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
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
	return isTokenByte(b) || b == '.'
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
