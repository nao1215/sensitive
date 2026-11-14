package detector

// AWSKeyType identifies the credential type in [AWSKeyDetail.KeyType].
type AWSKeyType string

const (
	// AWSKeyTypeLongTerm identifies long-term IAM user credentials (AKIA prefix).
	AWSKeyTypeLongTerm AWSKeyType = "long_term"
	// AWSKeyTypeTemporary identifies temporary STS credentials (ASIA prefix).
	AWSKeyTypeTemporary AWSKeyType = "temporary"
)

// AWSKeyDetail holds AWS Access Key-specific detail information.
type AWSKeyDetail struct {
	// KeyType is the credential type inferred from the prefix.
	KeyType AWSKeyType
}

// AWSKey detects AWS Access Key IDs by format, without checking whether they authenticate.
//
//  1. Find AKIA (long-term IAM) or ASIA (temporary STS).
//  2. Require exactly 16 following uppercase ASCII letters or digits and token boundaries, for 20 characters total.
//  3. Score a match as 0.95 and record [AWSKeyDetail.KeyType].
type AWSKey struct{}

// NewAWSKey creates a new AWS Access Key detector.
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
		keyType, ok := matchAWSPrefix(data, i)
		if !ok {
			continue
		}

		// Word boundary: preceding character must not be alphanumeric.
		if i > 0 && isAlphaNum(data[i-1]) && !encodedSeparatorBefore(data, i) {
			continue
		}

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
			End:          i + 20,
			Confidence:   0.95,
			RawValue:     string(data[i : i+20]),
			Detail:       &AWSKeyDetail{KeyType: keyType},
		})

		i += 19
	}

	return findings
}

// matchAWSPrefix checks whether data[i:i+4] is "AKIA" or "ASIA".
func matchAWSPrefix(data []byte, i int) (AWSKeyType, bool) {
	if data[i] != 'A' {
		return "", false
	}
	if data[i+1] == 'K' && data[i+2] == 'I' && data[i+3] == 'A' {
		return AWSKeyTypeLongTerm, true
	}
	if data[i+1] == 'S' && data[i+2] == 'I' && data[i+3] == 'A' {
		return AWSKeyTypeTemporary, true
	}
	return "", false
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
