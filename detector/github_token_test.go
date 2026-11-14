package detector_test

import (
	"strings"
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestGitHubTokenDetector_Scan(t *testing.T) {
	t.Parallel()

	classic := "ghp_" + strings.Repeat("a", 36)
	oauth := "gho_" + strings.Repeat("B", 36)
	fineGrained := "github_pat_11ABCDE0000aaaaaAAAAAa_abcdefghij"

	d := detector.NewGitHubToken()
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantRaw string
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

func TestGitHubTokenDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewGitHubToken()
	tests := []struct {
		name     string
		input    string
		wantType detector.GitHubTokenType
	}{
		{"classic", "ghp_" + strings.Repeat("a", 36), detector.GitHubTokenClassic},
		{"fine-grained", "github_pat_11ABCDE0000aaaaaAAAAAa_abcdefghij", detector.GitHubTokenFineGrained},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := d.Scan([]byte(tt.input))
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			detail, ok := findings[0].GitHubTokenDetail()
			if !ok {
				t.Fatalf("GitHubTokenDetail() ok = false")
			}
			if detail.TokenType != tt.wantType {
				t.Errorf("TokenType = %q, want %q", detail.TokenType, tt.wantType)
			}
			if findings[0].Kind() != detector.KindCredential {
				t.Errorf("Kind = %q, want credential", findings[0].Kind())
			}
		})
	}
}
