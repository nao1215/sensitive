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

			assertDetectorScan(t, d, tt.input, tt.wantLen, tt.wantRaw, tt.wantMinCon)
		})
	}
}

func TestAWSKeyDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewAWSKey()
	tests := []struct {
		input string
	}{
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		{input: sampleAccessKey},
		// #nosec G101 -- This public synthetic credential is a positive detection fixture, not an authentication secret.
		{input: "ASIAIMOSTEMPKEY12345"},
	}
	for _, tt := range tests {
		findings := d.Scan([]byte(tt.input))
		if len(findings) != 1 {
			t.Fatalf("input=%q: got %d findings, want 1", tt.input, len(findings))
		}
		if !matchAWSPrefix([]byte(tt.input), 0) || findings[0].Start != 0 || findings[0].End != len(tt.input) {
			t.Fatal(findings)
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
	if len(hints) != 4 {
		t.Errorf("Hints() returned %d hints, want 4", len(hints))
	}
}

func TestAWSKeyDetector_AccessKeyIDPrefixes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		text string
		want int
	}{
		{"id=ABIA4IJJUBZ7XCVN5NKX end", 1},
		{"id=ACCA4KVAPB54O5JEN3ZV end", 1},
		{"id=AGPA4KVAPB54O5JEN3ZV end", 0},
		{"id=XBIA4IJJUBZ7XCVN5NKX end", 0},
	} {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			if got := len(NewAWSKey().Scan([]byte(tc.text))); got != tc.want {
				t.Errorf("Scan(%q) returned %d findings, want %d", tc.text, got, tc.want)
			}
		})
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
