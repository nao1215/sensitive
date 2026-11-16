package detect

import (
	"strings"
	"testing"
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

	d := NewPrivateKeyPEM()
	tests := []struct {
		name     string
		input    string
		wantRaw  string
		wantAlgo string
		wantLen  int
	}{
		{
			name:     "RSA private key header",
			input:    pemHeader("RSA") + "\nMIIEow...\n-----END RSA PRIVATE KEY-----",
			wantLen:  1,
			wantRaw:  pemHeader("RSA") + "\nMIIEow...\n-----END RSA PRIVATE KEY-----",
			wantAlgo: "RSA",
		},
		{
			name:     "PKCS8 private key header (no algorithm)",
			input:    "config:\n" + pemHeader("") + "\n...",
			wantLen:  1,
			wantRaw:  pemHeader("") + "\n...",
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
			//nolint:goconst // Each test states its fixture and expected result independently.
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

func TestPEMHeaderVectors(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"} {
		raw := "-----BEGIN " + kind + "-----"
		got := NewPrivateKeyPEM().Scan([]byte(raw))
		if len(got) != 1 || got[0].RawValue != raw {
			t.Fatalf("private header rejected: %s", kind)
		}
		bad := strings.Replace(raw, "PRIVATE", "PUBLIC", 1)
		if len(NewPrivateKeyPEM().Scan([]byte(bad))) != 0 {
			t.Fatal("public header accepted")
		}
	}
}

func TestPEMIncompleteBlockMasksFollowingInput(t *testing.T) {
	t.Parallel()
	first := pemHeader("")
	second := first + "\nFAKE\n-----END PRIVATE KEY-----"
	got := NewPrivateKeyPEM().Scan([]byte(first + "\n" + second))
	if len(got) != 1 || got[0].RawValue != first+"\n"+second {
		t.Fatalf("wrong block bounds: %v", got)
	}
}

func TestPrivateKeyPemRejectedBoundaries(t *testing.T) {
	t.Parallel()
	if indexOf([]byte("-----BEGIN unterminated"), 0, "PRIVATE KEY-----") != -1 {
		t.Fatal("unterminated header accepted")
	}
}
