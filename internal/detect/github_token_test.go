package detect

import (
	"strings"
	"testing"
)

func TestGitHubTokenDetector_Scan(t *testing.T) {
	t.Parallel()

	classic := "ghp_" + strings.Repeat("a", 36)
	oauth := "gho_" + strings.Repeat("B", 36)
	fineGrained := "github_pat_11ABCDE0000aaaaaAAAAAa_abcdefghij"

	d := NewGitHubToken()
	tests := []struct {
		name    string
		input   string
		wantRaw string
		wantLen int
	}{
		{
			name:    "classic personal access token",
			input:   "token = " + classic,
			wantLen: 1,
			wantRaw: classic,
		},
		{
			name:    "classic oauth token",
			input:   "GITHUB_TOKEN=" + oauth,
			wantLen: 1,
			wantRaw: oauth,
		},
		{
			name:    "fine-grained personal access token",
			input:   "auth: " + fineGrained,
			wantLen: 1,
			wantRaw: fineGrained,
		},

		// False positives
		{
			name:    "classic prefix with too few body chars",
			input:   "ghp_" + strings.Repeat("a", 20),
			wantLen: 0,
		},
		{
			name:    "fine-grained prefix with too few body chars",
			input:   "github_pat_short",
			wantLen: 0,
		},
		{
			name:    "prefix embedded in a longer identifier",
			input:   "xghp_" + strings.Repeat("a", 36),
			wantLen: 0,
		},
		{
			name:    "unrelated text",
			input:   "just a normal sentence with no token",
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
			if tt.wantLen == 1 && tt.input[findings[0].Start:findings[0].End] != tt.wantRaw {
				t.Errorf("matched text = %q, want %q", tt.input[findings[0].Start:findings[0].End], tt.wantRaw)
			}
		})
	}
}

func TestGitHubTokenDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewGitHubToken()
	tests := []struct {
		name  string
		input string
	}{
		{name: "classic", input: "ghp_" + strings.Repeat("a", 36)},
		{name: "fine-grained", input: "github_pat_11ABCDE0000aaaaaAAAAAa_abcdefghij"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := d.Scan([]byte(tt.input))
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].DetectorName != NameGitHubToken || findings[0].Start != 0 || findings[0].End != len(tt.input) {
				t.Fatal(findings)
			}
		})
	}
}
