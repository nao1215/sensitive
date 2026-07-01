package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

// pemHeader builds a PEM "BEGIN" header for the given algorithm (empty for a bare
// PKCS#8 key). It assembles the string from parts so the full literal is never
// present in source — a fictitious test fixture must not trip secret scanners.
func pemHeader(algo string) string {
	prefix := "-----BEGIN "
	if algo != "" {
		prefix += algo + " "
	}
	return prefix + "PRIVATE" + " KEY-----"
}

func TestPrivateKeyPEMDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewPrivateKeyPEM()
	tests := []struct {
		name     string
		input    string
		wantLen  int
		wantRaw  string
		wantAlgo string
	}{
		{
			name:     "RSA private key header",
			input:    pemHeader("RSA") + "\nMIIEow...\n-----END RSA PRIVATE KEY-----",
			wantLen:  1,
			wantRaw:  pemHeader("RSA"),
			wantAlgo: "RSA",
		},
		{
			name:     "PKCS8 private key header (no algorithm)",
			input:    "config:\n" + pemHeader("") + "\n...",
			wantLen:  1,
			wantRaw:  pemHeader(""),
			wantAlgo: "",
		},
		{
			name:     "OpenSSH private key header",
			input:    pemHeader("OPENSSH"),
			wantLen:  1,
			wantRaw:  pemHeader("OPENSSH"),
			wantAlgo: "OPENSSH",
		},

		// False positives
		{
			name:    "public key header is not matched",
			input:   "-----BEGIN PUBLIC KEY-----",
			wantLen: 0,
		},
		{
			name:    "begin without closing dashes on the line",
			input:   "-----BEGIN RSA PRIVATE" + " KEY\nbody",
			wantLen: 0,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen == 0 {
				return
			}
			if findings[0].RawValue != tt.wantRaw {
				t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
			}
			detail, ok := findings[0].PrivateKeyPEMDetail()
			if !ok {
				t.Fatalf("PrivateKeyPEMDetail() ok = false")
			}
			if detail.KeyType != tt.wantAlgo {
				t.Errorf("KeyType = %q, want %q", detail.KeyType, tt.wantAlgo)
			}
		})
	}
}
