package detect

import (
	"cmp"
	"slices"
)

// Credential implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindCredential.
type Credential struct {
	// MatchKey optionally replaces the default assignment-key policy.
	MatchKey func(string) bool
}

// Name returns the credential detection family.
func (*Credential) Name() DetectorName { return NameCredential }

// Hints returns delimiters required by every supported credential form.
func (*Credential) Hints() [][]byte {
	return [][]byte{[]byte(":"), []byte("="), []byte("AKIA"), []byte("ASIA"), []byte("Bearer "), []byte("Basic ")}
}

func (d *Credential) scanPlain(data []byte) []Finding {
	urls := urlPasswords(data)
	out := slices.Clone(urls)
	urlIndex := 0
	contextAt, formatted := 0, false
	for i := 0; i < len(data); i++ {
		if data[i] != ':' && data[i] != '=' {
			continue
		}
		for urlIndex < len(urls) && urls[urlIndex].Start <= i {
			urlIndex++
		}
		// A userinfo username can itself be "token" or "password". Its
		// colon belongs to the URL, not an assignment extending past the host.
		if data[i] == ':' && urlIndex < len(urls) && urls[urlIndex].Start == i+1 {
			continue
		}
		key := d.credentialKey(data, i)
		if key == nil {
			continue
		}
		name := NormalizeCredentialKey(string(key))
		if name == credentialTokenKey && unquotedObjectValue(data, i+1) {
			continue
		}
		// Visit each context byte once, including values skipped by this loop.
		// Long keys and preceding fields must not lose their enclosing fmt shape.
		formatted = fmtCredentialContext(data[contextAt:i], formatted)
		contextAt = i
		start, end := assignmentValue(data, i+1, name, data[i] == ':' && formatted)
		if end > start && !redactedCredentialValue(data[start:end]) && (name != credentialTokenKey || !objectReference(data, start, end)) {
			out = append(out, credentialFinding(start, end))
			i = end - 1
		}
	}
	out = append(out, formattedURLPasswords(data)...)
	out = append(out, awsSecretPair(data)...)
	out = append(out, quotedAuthorization(data)...)
	// Context and assignment recognizers may identify the same credential.
	slices.SortFunc(out, func(a, b Finding) int {
		if n := cmp.Compare(a.Start, b.Start); n != 0 {
			return n
		}
		return cmp.Compare(a.End, b.End)
	})
	return slices.CompactFunc(out, func(a, b Finding) bool { return a.Start == b.Start && a.End == b.End })
}

func credentialFinding(start, end int) Finding {
	//nolint:mnd // Context identifies a credential; the score is a heuristic, not probability.
	return Finding{DetectorName: NameCredential, Start: start, End: end, Confidence: 0.95}
}

// awsSecretPair recognizes a 40-byte base64 secret within 128 bytes of an AWS
// access key ID. It does not infer ownership or validate credentials remotely.
func awsSecretPair(data []byte) []Finding {
	const awsContextBytes = 128
	var out []Finding
	for _, id := range NewAWSKey().Scan(data) {
		left, right := max(0, id.Start-awsContextBytes), min(len(data), id.End+awsContextBytes)
		for i := left; i < right; {
			if !awsSecretByte(data[i]) {
				i++
				continue
			}
			end := i + 1
			for end < right && awsSecretByte(data[end]) {
				end++
			}
			if end-i == 40 && (i == 0 || !awsSecretByte(data[i-1])) && (end == len(data) || !awsSecretByte(data[end])) {
				out = append(out, credentialFinding(i, end))
			}
			i = end
		}
	}
	return out
}

func awsSecretByte(b byte) bool { return isAlphaNum(b) || b == '+' || b == '/' }
