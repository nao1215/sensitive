package detector_test

import (
	"math/rand/v2"
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

func TestGeneratedGoogleAPIKey(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1215, 2026))
	body := func(n int) string {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		result := make([]byte, n)
		for i := range result {
			result[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return string(result)
	}
	for range 100 {
		raw := "AIza" + body(35)
		got := detector.NewGoogleAPIKey().Scan([]byte(raw))
		if len(got) != 1 || got[0].RawValue != raw || got[0].Confidence < 0.9 {
			t.Fatalf("valid generated value rejected: %v", got)
		}
		if len(detector.NewGoogleAPIKey().Scan([]byte("word"+raw))) != 0 {
			t.Fatal("embedded identifier accepted")
		}
	}
}
