package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestSlackTokenDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewSlackToken()
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantRaw string
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
			if tt.wantLen == 1 && findings[0].RawValue != tt.wantRaw {
				t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
			}
		})
	}
}

func TestSlackTokenDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewSlackToken()
	tests := []struct {
		input    string
		wantType detector.SlackTokenType
	}{
		{"xoxb-1234567890-abcdefghijkl", detector.SlackTokenBot},
		{"xoxp-1234567890-abcdefghijkl", detector.SlackTokenUser},
		{"xoxa-1234567890-abcdefghijkl", detector.SlackTokenApp},
		{"xoxr-1234567890-abcdefghijkl", detector.SlackTokenRefresh},
	}
	for _, tt := range tests {
		t.Run(string(tt.wantType), func(t *testing.T) {
			t.Parallel()
			findings := d.Scan([]byte(tt.input))
			if len(findings) != 1 {
				t.Fatalf("input=%q: got %d findings, want 1", tt.input, len(findings))
			}
			detail, ok := findings[0].SlackTokenDetail()
			if !ok {
				t.Fatalf("SlackTokenDetail() ok = false")
			}
			if detail.TokenType != tt.wantType {
				t.Errorf("TokenType = %q, want %q", detail.TokenType, tt.wantType)
			}
		})
	}
}
