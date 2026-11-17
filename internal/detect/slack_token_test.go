package detect

import (
	"testing"
)

func TestSlackTokenDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewSlackToken()
	tests := []struct {
		name    string
		input   string
		wantRaw string
		wantLen int
	}{
		{
			name:    "bot token",
			input:   "SLACK_TOKEN=xoxb-1234567890-abcdefghijkl",
			wantLen: 1,
			wantRaw: "xoxb-1234567890-abcdefghijkl",
		},
		{
			name:    "user token",
			input:   "token: xoxp-1111111111-2222222222-abcdef",
			wantLen: 1,
			wantRaw: "xoxp-1111111111-2222222222-abcdef",
		},

		// False positives
		{
			name:    "unknown type character",
			input:   "xoxz-1234567890-abcdefghijkl",
			wantLen: 0,
		},
		{
			name:    "missing dash after type",
			input:   "xoxb1234567890abcdefghijkl",
			wantLen: 0,
		},
		{
			name:    "body too short",
			input:   "xoxb-123",
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
			assertScanMatch(t, d, tt.input, tt.wantLen, tt.wantRaw)
		})
	}
}

func TestSlackTokenDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewSlackToken()
	tests := []struct {
		input string
	}{
		{input: "xoxb-1234567890-abcdefghijkl"},
		{input: "xoxp-1234567890-abcdefghijkl"},
		{input: "xoxa-1234567890-abcdefghijkl"},
		{input: "xoxr-1234567890-abcdefghijkl"},
		{input: "xoxe-1-1234567890-abcdefghijkl"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			findings := d.Scan([]byte(tt.input))
			if len(findings) != 1 {
				t.Fatalf("input=%q: got %d findings, want 1", tt.input, len(findings))
			}
			if !slackTokenPrefix([]byte(tt.input), 0) || findings[0].Start != 0 || findings[0].End != len(tt.input) {
				t.Fatal(findings)
			}
		})
	}
}
