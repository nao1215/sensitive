package detector_test

import (
	"strings"
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestGoogleAPIKeyDetector_Scan(t *testing.T) {
	t.Parallel()

	key := "AIza" + strings.Repeat("a", 35)

	d := detector.NewGoogleAPIKey()
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantRaw string
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
			if tt.wantLen == 1 && tt.wantRaw != "" && findings[0].RawValue != tt.wantRaw {
				t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
			}
			if tt.wantLen == 1 {
				if _, ok := findings[0].GoogleAPIKeyDetail(); !ok {
					t.Errorf("GoogleAPIKeyDetail() ok = false")
				}
			}
		})
	}
}
