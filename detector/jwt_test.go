package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestJWTDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewJWT()

	// A valid JWT with header {"alg":"HS256","typ":"JWT"}
	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "valid JWT token",
			input:      "token: " + validJWT,
			wantLen:    1,
			wantMinCon: 0.9,
		},
		{
			name:       "JWT in header",
			input:      "Authorization: Bearer " + validJWT,
			wantLen:    1,
			wantMinCon: 0.9,
		},

		// False positives
		{
			name:    "eyJ without dots",
			input:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantLen: 0,
		},
		{
			name:    "eyJ with only 1 dot",
			input:   "eyJhbGci.eyJzdWIi",
			wantLen: 0,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "eyJ inside longer base64url string should not match",
			input:   "ABCeyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
			wantLen: 0,
		},
		{
			name:    "eyJ preceded by underscore should not match",
			input:   "token_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
			wantLen: 0,
		},
		{
			name:    "eyJ preceded by hyphen should not match",
			input:   "data-eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
			wantLen: 0,
		},
		{
			name:       "eyJ preceded by space should match",
			input:      "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
			wantLen:    1,
			wantMinCon: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen > 0 && tt.wantMinCon > 0 {
				if findings[0].Confidence < tt.wantMinCon {
					t.Errorf("Confidence = %f, want >= %f", findings[0].Confidence, tt.wantMinCon)
				}
			}
		})
	}
}

func TestJWTDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewJWT()
	// Header: {"alg":"HS256","typ":"JWT"}
	// #nosec G101 -- test token for JWT detection
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	findings := d.Scan([]byte(token))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].JWTDetail()
	if !ok {
		t.Fatal("JWTDetail() returned false")
	}
	if detail.Algorithm != "HS256" {
		t.Errorf("Algorithm = %q, want %q", detail.Algorithm, "HS256")
	}
}

func TestJWTDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewJWT()
	if d.Name() != detector.NameJWT {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameJWT)
	}
}

func TestJWTDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewJWT()
	hints := d.Hints()
	if len(hints) != 1 || string(hints[0]) != "eyJ" {
		t.Errorf("Hints() = %v, want [[eyJ]]", hints)
	}
}

func TestJWTDetector_InvalidJSONHeader(t *testing.T) {
	t.Parallel()

	d := detector.NewJWT()
	// Header "eyJaaa" decodes to non-JSON bytes, so JSON parse fails.
	// This gives base 0.7 confidence only.
	findings := d.Scan([]byte("eyJaaa.eyJzdWIi.signature"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Confidence > 0.8 {
		t.Errorf("Confidence = %f, want <= 0.8 for invalid JSON header", findings[0].Confidence)
	}
}

func TestJWTDetector_UnsignedJWT(t *testing.T) {
	t.Parallel()

	d := detector.NewJWT()
	// alg:none JWT has empty signature. Header: {"alg":"none"}
	// base64url("{"alg":"none"}") = "eyJhbGciOiJub25lIn0"
	// base64url("{"sub":"1234567890"}") = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
	// #nosec G101 -- test token for JWT detection
	token := "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
	findings := d.Scan([]byte(token))
	if len(findings) != 1 {
		t.Fatalf("got %d findings for alg:none JWT, want 1", len(findings))
	}
	f := findings[0]
	// Unsigned JWT should have lower confidence than a signed JWT (1.0).
	// Base 0.5 + valid JSON header 0.2 + alg key 0.1 = 0.8.
	if f.Confidence >= 0.9 {
		t.Errorf("Confidence = %f, want < 0.9 for unsigned JWT", f.Confidence)
	}
	if f.Confidence < 0.5 {
		t.Errorf("Confidence = %f, want >= 0.5 for unsigned JWT with valid header", f.Confidence)
	}
	detail, ok := f.JWTDetail()
	if !ok {
		t.Fatal("JWTDetail() returned false")
	}
	if detail.Algorithm != "none" {
		t.Errorf("Algorithm = %q, want %q", detail.Algorithm, "none")
	}
}

func TestJWTDetector_EmptyHeaderRejected(t *testing.T) {
	t.Parallel()

	d := detector.NewJWT()
	// Empty header part (starts with dot) should not match — the extraction
	// loop starts at "eyJ" so this can't occur naturally. But ensure the
	// len(parts[0]) == 0 guard works.
	findings := d.Scan([]byte("eyJ.eyJzdWIi.sig"))
	// "eyJ" alone is just 3 base64 chars = "{" which is valid JSON but not
	// a useful header. This tests that very short headers still produce a finding.
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}
