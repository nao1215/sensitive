package detect

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
		if i > 0 && isAlphaNum(data[i-1]) && !encodedSeparatorBefore(data, i) {
			continue
		}

		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if !validateAWSKeyBody(data, i+4) {
			continue
		}

		// Word boundary: following character must not be alphanumeric.
		if i+20 < len(data) && isAlphaNum(data[i+20]) {
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

// matchAWSPrefix checks whether data[i:i+4] is "AKIA" or "ASIA".
func matchAWSPrefix(data []byte, i int) bool {
	if data[i] != 'A' {
		return false
	}
	if data[i+1] == 'K' && data[i+2] == 'I' && data[i+3] == 'A' {
		return true
	}
	if data[i+1] == 'S' && data[i+2] == 'I' && data[i+3] == 'A' {
		return true
	}
	return false
}

// validateAWSKeyBody checks that 16 characters starting at data[start] are
// uppercase alphanumeric (A-Z, 0-9).
func validateAWSKeyBody(data []byte, start int) bool {
	if start+16 > len(data) {
		return false
	}
	for k := start; k < start+16; k++ {
		if !isUpperAlphaNum(data[k]) {
			return false
		}
	}
	return true
}

// isUpperAlphaNum reports whether b is an uppercase ASCII letter or digit.
func isUpperAlphaNum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
