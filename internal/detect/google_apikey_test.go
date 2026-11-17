package detect

import (
	"strings"
	"testing"
)

func TestGoogleAPIKeyDetector_Scan(t *testing.T) {
	t.Parallel()

	key := "AIza" + strings.Repeat("a", 35)

	d := NewGoogleAPIKey()
	tests := []struct {
		name    string
		input   string
		wantRaw string
		wantLen int
	}{
		{
			name:    "google api key",
			input:   "GOOGLE_API_KEY=" + key,
			wantLen: 1,
			wantRaw: key,
		},
		{
			name:    "key with dash and underscore in body",
			input:   "key: AIza" + strings.Repeat("a", 20) + "-_" + strings.Repeat("b", 13),
			wantLen: 1,
		},

		// False positives
		{
			name:    "body too short",
			input:   "AIza" + strings.Repeat("a", 20),
			wantLen: 0,
		},
		{
			name:    "prefix embedded in a longer token",
			input:   "xAIza" + strings.Repeat("a", 35),
			wantLen: 0,
		},
		{
			name:    "unrelated text",
			input:   "AIzawa is a Japanese surname, not a key",
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
			if tt.wantLen == 1 && tt.wantRaw != "" && tt.input[findings[0].Start:findings[0].End] != tt.wantRaw {
				t.Errorf("matched text = %q, want %q", tt.input[findings[0].Start:findings[0].End], tt.wantRaw)
			}
		})
	}
}
