package detect

import (
	"testing"
)

func TestAWSKeyDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		{
			name:       "AKIA prefix key",
			input:      "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			wantLen:    1,
			wantRaw:    sampleAccessKey,
			wantMinCon: 0.9,
		},
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		{
			name:       "ASIA prefix key (STS)",
			input:      "key: ASIAIMOSTEMPKEY12345",
			wantLen:    1,
			wantRaw:    "ASIAIMOSTEMPKEY12345",
			wantMinCon: 0.9,
		},

		// False positives
		{
			name:    "AKIA with too few following chars",
			input:   "AKIA1234",
			wantLen: 0,
		},
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		{
			name:    "AKIA inside longer token",
			input:   "xAKIAIOSFODNN7EXAMPLE",
			wantLen: 0,
		},
		{
			name:    "lowercase akia",
			input:   "akiaiosfodnn7example",
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
			if tt.wantLen > 0 && tt.wantRaw != "" {
				if findings[0].RawValue != tt.wantRaw {
					t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
				}
			}
			if tt.wantLen > 0 && tt.wantMinCon > 0 {
				if findings[0].Confidence < tt.wantMinCon {
					t.Errorf("Confidence = %f, want >= %f", findings[0].Confidence, tt.wantMinCon)
				}
			}
		})
	}
}

func TestAWSKeyDetector_Detail(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	tests := []struct {
		input    string
		wantType AWSKeyType
	}{
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		{input: sampleAccessKey, wantType: AWSKeyTypeLongTerm},
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		{input: "ASIAIMOSTEMPKEY12345", wantType: AWSKeyTypeTemporary},
	}
	for _, tt := range tests {
		findings := d.Scan([]byte(tt.input))
		if len(findings) != 1 {
			t.Fatalf("input=%q: got %d findings, want 1", tt.input, len(findings))
		}
		detail, ok := findings[0].AWSKeyDetail()
		if !ok {
			t.Fatalf("input=%q: AWSKeyDetail() returned false", tt.input)
		}
		if detail.KeyType != tt.wantType {
			t.Errorf("input=%q: KeyType = %q, want %q", tt.input, detail.KeyType, tt.wantType)
		}
	}
}

func TestAWSKeyDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	if d.Name() != NameAWSKey {
		t.Errorf("Name() = %q, want %q", d.Name(), NameAWSKey)
	}
}

func TestAWSKeyDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	hints := d.Hints()
	if len(hints) != 2 {
		t.Errorf("Hints() returned %d hints, want 2", len(hints))
	}
}

func TestAWSKeyDetector_FollowedByAlphaNum(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	findings := d.Scan([]byte("AKIAIOSFODNN7EXAMPLEX"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for key followed by alpha, want 0", len(findings))
	}
}

func TestAWSKeyDetector_LowercaseInSuffix(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	findings := d.Scan([]byte("AKIAiosfodnn7example"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for lowercase suffix, want 0", len(findings))
	}
}

func TestAWSKeyDetector_MultipleKeys(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	findings := d.Scan([]byte("AKIAIOSFODNN7EXAMPLE ASIAIMOSTEMPKEY12345"))
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
}

func TestAWSKeyDetector_TruncatedKey(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	// Key with only 19 chars (missing last char).
	findings := d.Scan([]byte("AKIAIOSFODNN7EXAMPL"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for truncated key, want 0", len(findings))
	}
}

func TestAWSKeyDetector_NonAKIAPrefix(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	// ANPA prefix should not match.
	findings := d.Scan([]byte("ANPAIOSFODNN7EXAMPLE"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for ANPA prefix, want 0", len(findings))
	}
}

func TestAwskeyRejectedBoundaries(t *testing.T) {
	t.Parallel()
	if validateAWSKeyBody([]byte("AKIA"), 4) {
		t.Fatal("truncated key body accepted")
	}
}
