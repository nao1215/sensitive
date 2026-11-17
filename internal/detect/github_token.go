package detect

// GitHubToken implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindGitHubToken.
type GitHubToken struct{}

// NewGitHubToken recognizes GitHub token prefixes and their required body lengths.
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
		if !credStartBoundary(data, i) {
			i++
			continue
		}
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
	end, n := scanCharset(data, i+len(prefix), isIdentifierByte)
	if n < githubFineGrainedMinBody || !credBoundary(data, i, end) {
		return Finding{}, 0, false
	}
	return d.finding(i, end), end, true
}

// matchClassic tries to match a classic token at index i.
func (d *GitHubToken) matchClassic(data []byte, i int) (Finding, int, bool) {
	for _, prefix := range d.classicPrefixes() {
		if !hasASCIIPrefix(data, i, prefix) {
			continue
		}
		end, n := scanCharset(data, i+len(prefix), isAlphaNum)
		if n != githubClassicBodyLen || !credBoundary(data, i, end) {
			return Finding{}, 0, false
		}
		return d.finding(i, end), end, true
	}
	return Finding{}, 0, false
}

func (d *GitHubToken) finding(start, end int) Finding {
	return Finding{
		DetectorName: d.Name(),
		Start:        start,
		End:          end,
		//nolint:mnd // The detector contract documents this heuristic score.
		Confidence: 0.95,
	}
}
