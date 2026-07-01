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

// GitHubToken detects GitHub access tokens in text.
//
// GitHub tokens come in two shapes:
//
//   - Classic tokens use a four-character prefix identifying the token kind —
//     "ghp_" (personal access token), "gho_" (OAuth access token), "ghu_"
//     (user-to-server), "ghs_" (server-to-server), or "ghr_" (refresh token) —
//     followed by 36 base62 characters (A-Z, a-z, 0-9).
//   - Fine-grained personal access tokens use the "github_pat_" prefix followed
//     by at least 22 characters of A-Z, a-z, 0-9, or '_'.
//
// Detection logic:
//  1. Scan for one of the six known prefixes (fine-grained is tried first so its
//     longer prefix is not misread as a classic one).
//  2. Validate that the token body matches the expected character set and minimum
//     length for that prefix.
//  3. Enforce word boundaries so a token embedded in a longer identifier is not
//     matched.
//
// Confidence: 0.95 — the prefixes are highly specific to GitHub.
type GitHubToken struct{}

// NewGitHubToken creates a new GitHub token detector.
func NewGitHubToken() *GitHubToken {
	return &GitHubToken{}
}

// Name returns "github_token".
func (d *GitHubToken) Name() DetectorName {
	return NameGitHubToken
}

// Hints returns byte sequences for pre-filtering. Every GitHub token contains one
// of these prefixes, so they are exhaustive for the detector's domain.
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

// Scan examines data for GitHub tokens and returns findings.
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
		if n < githubClassicBodyLen || !credBoundary(data, i, end) {
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
