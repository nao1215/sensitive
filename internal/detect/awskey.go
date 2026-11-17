package detect

import "github.com/nao1215/embargo/internal/ascii"

// AWSKey implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindAWSKey.
type AWSKey struct{}

// NewAWSKey recognizes long-term and temporary access-key ID prefixes.
func NewAWSKey() *AWSKey {
	return &AWSKey{}
}

// Name returns "awskey".
func (d *AWSKey) Name() DetectorName {
	return NameAWSKey
}

// Hints returns the pre-filter substrings for [AWSKey].
func (d *AWSKey) Hints() [][]byte {
	return [][]byte{
		[]byte("AKIA"),
		[]byte("ASIA"),
		[]byte("ABIA"),
		[]byte("ACCA"),
	}
}

// Scan returns matches in data using the rules documented on [AWSKey].
func (d *AWSKey) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-19; i++ {
		if !matchAWSPrefix(data, i) {
			continue
		}

		// Word boundary: preceding character must not be alphanumeric.
		if i > 0 && ascii.IsAlphaNum(data[i-1]) && !encodedSeparatorBefore(data, i) {
			continue
		}

		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if !validateAWSKeyBody(data, i+4) {
			continue
		}

		// Word boundary: following character must not be alphanumeric.
		if i+20 < len(data) && ascii.IsAlphaNum(data[i+20]) {
			continue
		}

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
			End: i + 20,
			//nolint:mnd // The detector contract documents this heuristic score.
			Confidence: 0.95,
		})

		i += 19
	}

	return findings
}

// matchAWSPrefix checks whether data[i:i+4] is an access-key ID prefix:
// AKIA (long-term), ASIA (temporary), ABIA (STS service bearer) or ACCA
// (context-specific credential).
func matchAWSPrefix(data []byte, i int) bool {
	if data[i] != 'A' {
		return false
	}
	switch string(data[i+1 : i+4]) {
	case "KIA", "SIA", "BIA", "CCA":
		return true
	default:
		return false
	}
}

// validateAWSKeyBody checks that 16 characters starting at data[start] are
// uppercase alphanumeric (A-Z, 0-9).
func validateAWSKeyBody(data []byte, start int) bool {
	if start+16 > len(data) {
		return false
	}
	for k := start; k < start+16; k++ {
		if !ascii.IsUpper(data[k]) && !ascii.IsDigit(data[k]) {
			return false
		}
	}
	return true
}
