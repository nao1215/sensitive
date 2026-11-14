package detector

// GitHubTokenType classifies a detected GitHub token by its prefix family.
// Use the GitHubToken* constants for comparison with [GitHubTokenDetail.TokenType].
type GitHubTokenType string

const (
	// GitHubTokenClassic identifies a classic token: a personal access token
	// (ghp_), OAuth access token (gho_), user-to-server (ghu_), server-to-server
	// (ghs_), or refresh token (ghr_).
	GitHubTokenClassic GitHubTokenType = "classic"
	// GitHubTokenFineGrained identifies a fine-grained personal access token
	// (github_pat_).
	GitHubTokenFineGrained GitHubTokenType = "fine_grained"
)

// GitHubTokenDetail holds GitHub token-specific detail information.
type GitHubTokenDetail struct {
	// TokenType is the token family inferred from the prefix.
	TokenType GitHubTokenType
}

// GitHubToken detects GitHub access tokens by format, without verifying authentication.
//
//  1. Find github_pat_ first, or a classic prefix: ghp_, gho_, ghu_, ghs_, or ghr_.
//  2. Require exactly 36 ASCII alphanumeric body characters for classic tokens, or at least 22 ASCII alphanumerics/underscores for fine-grained tokens.
//  3. Enforce word boundaries and score a match as 0.95; [GitHubTokenType] identifies the family.
type GitHubToken struct{}

// NewGitHubToken creates a new GitHub token detector.
func NewGitHubToken() *GitHubToken {
	return &GitHubToken{}
}

// Name returns "github_token".
func (d *GitHubToken) Name() DetectorName {
	return NameGitHubToken
}

// Hints returns the pre-filter substrings for [GitHubToken].
func (d *GitHubToken) Hints() [][]byte {
	return [][]byte{
		[]byte("ghp_"),
		[]byte("gho_"),
		[]byte("ghu_"),
		[]byte("ghs_"),
		[]byte("ghr_"),
		[]byte("github_pat_"),
	}
}

// classicPrefixes are the four-character classic-token prefixes.
func (d *GitHubToken) classicPrefixes() []string {
	return []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}
}

// githubClassicBodyLen is the number of base62 characters after a classic prefix.
const githubClassicBodyLen = 36

// githubFineGrainedMinBody is the minimum body length after "github_pat_".
const githubFineGrainedMinBody = 22

// Scan returns matches in data using the rules documented on [GitHubToken].
func (d *GitHubToken) Scan(data []byte) []Finding {
	var findings []Finding
	for i := 0; i < len(data); {
		if f, end, ok := d.matchFineGrained(data, i); ok {
			findings = append(findings, f)
			i = end
			continue
		}
		if f, end, ok := d.matchClassic(data, i); ok {
			findings = append(findings, f)
			i = end
			continue
		}
		i++
	}
	return findings
}

// matchFineGrained tries to match a fine-grained PAT at index i.
func (d *GitHubToken) matchFineGrained(data []byte, i int) (Finding, int, bool) {
	const prefix = "github_pat_"
	if !hasASCIIPrefix(data, i, prefix) {
		return Finding{}, 0, false
	}
	end, n := scanCharset(data, i+len(prefix), isBase62OrUnderscore)
	if n < githubFineGrainedMinBody || !credBoundary(data, i, end) {
		return Finding{}, 0, false
	}
	return d.finding(data, i, end, GitHubTokenFineGrained), end, true
}

// matchClassic tries to match a classic token at index i.
func (d *GitHubToken) matchClassic(data []byte, i int) (Finding, int, bool) {
	for _, prefix := range d.classicPrefixes() {
		if !hasASCIIPrefix(data, i, prefix) {
			continue
		}
		end, n := scanCharset(data, i+len(prefix), isBase62)
		if n != githubClassicBodyLen || !credBoundary(data, i, end) {
			return Finding{}, 0, false
		}
		return d.finding(data, i, end, GitHubTokenClassic), end, true
	}
	return Finding{}, 0, false
}

func (d *GitHubToken) finding(data []byte, start, end int, kind GitHubTokenType) Finding {
	return Finding{
		DetectorName: d.Name(),
		Start:        start,
		End:          end,
		Confidence:   0.95,
		RawValue:     string(data[start:end]),
		Detail:       &GitHubTokenDetail{TokenType: kind},
	}
}

// isBase62 reports whether b is an ASCII letter or digit.
func isBase62(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// isBase62OrUnderscore reports whether b is base62 or '_'.
func isBase62OrUnderscore(b byte) bool {
	return isBase62(b) || b == '_'
}
