package detector

import "strings"

// PrivateKeyPEMDetail holds PEM private key-specific detail information.
type PrivateKeyPEMDetail struct {
	// KeyType is the algorithm/format named in the PEM header (e.g. "RSA", "EC",
	// "OPENSSH", "DSA", or "" for a bare PKCS#8 "PRIVATE KEY").
	KeyType string
}

// PrivateKeyPEM detects PEM private key headers; the body is neither required nor parsed.
//
//  1. Find -----BEGIN and its following space.
//  2. Read through the closing ----- on the same line and require the header content to end with PRIVATE KEY.
//  3. Return the header with confidence 0.99 and record any preceding algorithm text (e.g., RSA, EC, DSA, OPENSSH, ENCRYPTED, or empty for bare PKCS#8).
type PrivateKeyPEM struct{}

// NewPrivateKeyPEM creates a new PEM private key detector.
func NewPrivateKeyPEM() *PrivateKeyPEM {
	return &PrivateKeyPEM{}
}

// Name returns "private_key_pem".
func (d *PrivateKeyPEM) Name() DetectorName {
	return NamePrivateKeyPEM
}

// Hints returns the pre-filter substrings for [PrivateKeyPEM].
func (d *PrivateKeyPEM) Hints() [][]byte {
	return [][]byte{[]byte("PRIVATE KEY")}
}

// Scan returns matches in data using the rules documented on [PrivateKeyPEM].
func (d *PrivateKeyPEM) Scan(data []byte) []Finding {
	const opener = "-----BEGIN "
	const closer = "-----"
	var findings []Finding
	for i := 0; i+len(opener) <= len(data); {
		if !hasASCIIPrefix(data, i, opener) {
			i++
			continue
		}
		contentStart := i + len(opener)
		rel := indexOf(data, contentStart, closer)
		if rel < 0 {
			i += len(opener)
			continue
		}
		content := string(data[contentStart:rel])
		if !strings.HasSuffix(content, "PRIVATE KEY") {
			i += len(opener)
			continue
		}
		end := rel + len(closer)
		algo := strings.TrimSpace(strings.TrimSuffix(content, "PRIVATE KEY"))
		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   0.99,
			RawValue:     string(data[i:end]),
			Detail:       &PrivateKeyPEMDetail{KeyType: algo},
		})
		i = end
	}
	return findings
}

// indexOf returns the index of the first occurrence of sub in data at or after
// start, or -1 if not found. It scans a single header line (stops at a newline)
// so an unterminated opener does not swallow the rest of the document.
func indexOf(data []byte, start int, sub string) int {
	for i := start; i+len(sub) <= len(data); i++ {
		if data[i] == '\n' {
			return -1
		}
		if hasASCIIPrefix(data, i, sub) {
			return i
		}
	}
	return -1
}
