package detector

// AWSKeyType is the type-safe identifier for an AWS key credential type.
// Use the AWSKeyType* constants for comparison with [AWSKeyDetail.KeyType].
//
//	if detail.KeyType == detector.AWSKeyTypeLongTerm { ... }
type AWSKeyType string

const (
	// AWSKeyTypeLongTerm identifies long-term IAM user credentials (AKIA prefix).
	AWSKeyTypeLongTerm AWSKeyType = "long_term"
	// AWSKeyTypeTemporary identifies temporary STS credentials (ASIA prefix).
	AWSKeyTypeTemporary AWSKeyType = "temporary"
)

// AWSKeyDetail holds AWS Access Key-specific detail information.
type AWSKeyDetail struct {
	// KeyType is the type of the AWS key.
	// Compare with the AWSKeyType* constants (e.g., [AWSKeyTypeLongTerm],
	// [AWSKeyTypeTemporary]).
	KeyType AWSKeyType
}

// AWSKey detects AWS Access Key IDs in text.
//
// AWS Access Key IDs are 20-character strings that start with "AKIA" (long-term
// credentials) or "ASIA" (temporary STS credentials). The remaining 16 characters
// are uppercase letters and digits (A-Z, 0-9).
//
// Detection logic:
//  1. Scan for "AKIA" or "ASIA" prefix
//  2. Validate that the next 16 characters are uppercase alphanumeric
//  3. Confirm total length is exactly 20 characters
//
// Confidence: 0.95 for a valid match.
type AWSKey struct{}

// NewAWSKey creates a new AWS Access Key detector.
func NewAWSKey() *AWSKey {
	return &AWSKey{}
}

// Name returns "awskey".
func (d *AWSKey) Name() DetectorName {
	return NameAWSKey
}

// Hints returns byte sequences for pre-filtering.
// AWS Access Key IDs always start with "AKIA" or "ASIA", providing
// highly specific hints for efficient pre-filtering.
func (d *AWSKey) Hints() [][]byte {
	return [][]byte{
		[]byte("AKIA"),
		[]byte("ASIA"),
	}
}

// Scan examines data for AWS Access Key IDs and returns findings.
func (d *AWSKey) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-19; i++ {
		// Check for AKIA or ASIA prefix.
		if data[i] != 'A' {
			continue
		}
		if i+3 >= len(data) {
			continue
		}

		isAKIA := data[i+1] == 'K' && data[i+2] == 'I' && data[i+3] == 'A'
		isASIA := data[i+1] == 'S' && data[i+2] == 'I' && data[i+3] == 'A'
		if !isAKIA && !isASIA {
			continue
		}

		// Check that the preceding character is not alphanumeric
		// (to avoid matching substrings of longer tokens).
		if i > 0 && isAlphaNum(data[i-1]) {
			continue
		}

		// Validate that the next 16 characters (after prefix) are uppercase alphanumeric.
		if i+20 > len(data) {
			continue
		}

		valid := true
		for k := i + 4; k < i+20; k++ {
			if !isUpperAlphaNum(data[k]) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}

		// Check that the character after the key is not alphanumeric.
		if i+20 < len(data) && isAlphaNum(data[i+20]) {
			continue
		}

		keyType := AWSKeyTypeLongTerm
		if isASIA {
			keyType = AWSKeyTypeTemporary
		}

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          i + 20,
			Confidence:   0.95,
			RawValue:     string(data[i : i+20]),
			Detail:       &AWSKeyDetail{KeyType: keyType},
		})

		i += 19 // Skip past the matched key.
	}

	return findings
}

// isUpperAlphaNum reports whether b is an uppercase ASCII letter or digit.
func isUpperAlphaNum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
