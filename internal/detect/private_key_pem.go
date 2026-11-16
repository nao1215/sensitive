package detect

import (
	"bytes"
	"strings"
)

// PrivateKeyPEMDetail holds PEM private key-specific detail information.
type PrivateKeyPEMDetail struct {
	// KeyType is the algorithm/format named in the PEM header (e.g. "RSA", "EC",
	// "OPENSSH", "DSA", or "" for a bare PKCS#8 "PRIVATE KEY").
	KeyType string
}

// PrivateKeyPEM implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindPrivateKeyPEM.
type PrivateKeyPEM struct{}

// NewPrivateKeyPEM retains the key body through its matching END marker when present.
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
	var findings []Finding
	for i := 0; i < len(data); {
		label, headerEnd := PEMHeader(data, i)
		if label == nil {
			i++
			continue
		}
		end, complete := PEMFooter(data, headerEnd, label)
		if !complete {
			end = len(data)
		}
		algo := strings.TrimSpace(strings.TrimSuffix(string(label), "PRIVATE KEY"))

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			//nolint:mnd // The detector contract documents this heuristic score.
			Confidence: 0.99,
			RawValue:   string(data[i:end]),
			Detail:     &PrivateKeyPEMDetail{KeyType: algo},
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

// PEMHeader recognizes a private-key frame in normalized input. The returned
// label aliases data and end is a normalized byte boundary, or zero on failure.
func PEMHeader(data []byte, start int) (label []byte, end int) {
	const opener = "-----BEGIN "
	const closer = "-----"
	if !hasASCIIPrefix(data, start, opener) {
		return nil, 0
	}
	labelStart := start + len(opener)
	stop := indexOf(data, labelStart, closer)
	if stop < 0 {
		return nil, 0
	}
	label = data[labelStart:stop]
	if !bytes.HasSuffix(label, []byte("PRIVATE KEY")) && string(label) != "PGP PRIVATE KEY BLOCK" {
		return nil, 0
	}
	return label, stop + len(closer)
}

// PEMFooter finds the matching normalized frame without constructing a second
// copy of its label. An incomplete block extends to the end of input.
func PEMFooter(data []byte, start int, label []byte) (end int, complete bool) {
	const opener = "-----END "
	const closer = "-----"
	for start < len(data) {
		at := bytes.Index(data[start:], []byte(opener))
		if at < 0 {
			break
		}
		at += start + len(opener)
		if bytes.HasPrefix(data[at:], label) && hasASCIIPrefix(data, at+len(label), closer) {
			return at + len(label) + len(closer), true
		}
		start = at
	}
	return len(data), false
}
