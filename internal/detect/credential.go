package detect

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/nao1215/embargo/internal/ascii"
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
	return [][]byte{[]byte(":"), []byte("="), []byte("</"), []byte("AKIA"), []byte("ASIA"), []byte("ABIA"), []byte("ACCA"), []byte("Bearer "), []byte("Basic "), []byte("--"), []byte("mysql"), []byte("mariadb"), []byte("sshpass")}
}

// Scan returns only secret spans, never their surrounding configuration fields.
func (d *Credential) Scan(data []byte) []Finding {
	out := d.scanPlain(data)
	input := data
	var positions []int
	const layers = 4
	for range layers {
		decoded, mapping := credentialQuotes(input)
		if mapping == nil {
			break
		}
		mapping = composePositions(mapping, positions)
		next := d.scanPlain(decoded)
		previous := 0
		added := make([]Finding, 0, len(next))
		for _, f := range next {
			f.Start, f.End = mapping[f.Start], mapping[f.End]
			// A valid less-escaped value owns its quotes. Decoding its interior again
			// must not reinterpret an escaped quote as the end of that value.
			for previous < len(out) && out[previous].End <= f.Start {
				previous++
			}
			if previous < len(out) && out[previous].Start < f.End && (f.Start >= out[previous].Start || f.End < out[previous].End) {
				continue
			}

			added = append(added, f)
		}
		out = append(out, added...)
		slices.SortFunc(out, func(a, b Finding) int { return cmp.Compare(a.Start, b.Start) })
		input, positions = decoded, mapping
	}
	return out
}

// scanView adds normalized assignments while raw URL delimiters retain ownership
// of percent-escaped userinfo. Mapping always refers to original input bytes.
func (d *Credential) scanView(v View) []Finding {
	out := d.Scan(v.Raw)
	if v.Positions == nil {
		return out
	}
	previous, rawCount := 0, len(out)
	for _, f := range d.Scan(v.Data) {
		f.Start, f.End = v.Positions[f.Start], v.Positions[f.End]
		for previous < rawCount && out[previous].End <= f.Start {
			previous++
		}
		if previous < rawCount && out[previous].Start < f.End && (f.Start >= out[previous].Start || f.End < out[previous].End) {
			continue
		}

		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Finding) int { return cmp.Compare(a.Start, b.Start) })
	return out
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
		var userinfo bool
		urlIndex, userinfo = urlUserinfoColon(data, urls, urlIndex, i)
		if userinfo {
			continue
		}
		name, ok := d.assignmentName(data, i)
		if !ok {
			continue
		}
		// Visit each context byte once, including values skipped by this loop.
		// Long keys and preceding fields must not lose their enclosing fmt shape.
		formatted = fmtCredentialContext(data[contextAt:i], formatted)
		contextAt = i
		start, end := assignmentValue(data, i+1, name, data[i] == ':' && formatted)
		if end > start && acceptedAssignmentValue(data, start, end, name) {
			out = append(out, credentialFinding(start, end))
			i = end - 1
		}
	}
	out = d.appendContextCredentials(out, data)
	// Context and assignment recognizers may identify the same credential.
	slices.SortFunc(out, func(a, b Finding) int {
		if n := cmp.Compare(a.Start, b.Start); n != 0 {
			return n
		}
		return cmp.Compare(a.End, b.End)
	})
	return slices.CompactFunc(out, func(a, b Finding) bool { return a.Start == b.Start && a.End == b.End })
}

// appendContextCredentials adds credentials recognized by their surrounding
// syntax rather than by an assignment separator.
func (d *Credential) appendContextCredentials(out []Finding, data []byte) []Finding {
	out = append(out, formattedURLPasswords(data)...)
	out = append(out, awsSecretPair(data)...)
	out = append(out, quotedAuthorization(data)...)
	out = append(out, d.xmlElementCredentials(data)...)
	out = append(out, curlUserPasswords(data)...)
	out = append(out, d.flagValues(data)...)
	return append(out, commandPasswords(data)...)
}

// urlUserinfoColon advances urlIndex past URL findings starting at or before i
// and reports whether the colon at i separates URL userinfo, not an assignment.
func urlUserinfoColon(data []byte, urls []Finding, urlIndex, i int) (int, bool) {
	for urlIndex < len(urls) && urls[urlIndex].Start <= i {
		urlIndex++
	}
	// A userinfo username can itself be "token" or "password". Its
	// colon belongs to the URL, not an assignment extending past the host.
	return urlIndex, data[i] == ':' && urlIndex < len(urls) && urls[urlIndex].Start == i+1
}

// assignmentName returns the normalized credential key ending at the
// separator i, rejecting a token key whose value is an unquoted object.
func (d *Credential) assignmentName(data []byte, i int) (string, bool) {
	key := d.credentialKey(data, i)
	if key == nil {
		return "", false
	}
	name := NormalizeCredentialKey(string(key))
	if name == credentialTokenKey && unquotedObjectValue(data, i+1) {
		return "", false
	}
	return name, true
}

// acceptedAssignmentValue rejects already redacted values, token values
// that only reference another object, and UUID idempotency tokens.
func acceptedAssignmentValue(data []byte, start, end int, name string) bool {
	return !redactedCredentialValue(data[start:end]) && (name != credentialTokenKey || !objectReference(data, start, end)) && !idempotencyToken(data, start, end, name) && !numericSessionID(data[start:end], name)
}

// numericSessionID reports a session key whose value is an integer, decimal
// or 0x hexadecimal, such as ZooKeeper's sessionid: 0x14edfaa86f60027. Such
// IDs name a session to the server log; web session cookies are random text.
func numericSessionID(value []byte, name string) bool {
	if name != "session" && name != "sessionid" {
		return false
	}
	digits := bytes.TrimPrefix(bytes.TrimPrefix(value, []byte("0x")), []byte("0X"))
	if len(digits) == 0 {
		return false
	}
	hex := len(digits) != len(value)
	for _, b := range digits {
		if !ascii.IsDigit(b) && (!hex || !ascii.IsHexDigit(b)) {
			return false
		}
	}
	return true
}

// idempotencyToken reports an AWS-style clientToken or idempotencyToken whose
// value is a canonical UUID. These keys deduplicate retried requests (EC2,
// CloudTrail requestParameters) and authenticate nothing.
func idempotencyToken(data []byte, start, end int, name string) bool {
	return (name == "clienttoken" || name == "idempotencytoken") && end-start == uuidLength && canonicalUUID(data, start)
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
		out = awsSecretsInWindow(data, left, right, out)
	}
	return out
}

// awsSecretsInWindow appends each standalone 40-byte secret run found in
// data[left:right]; run boundaries are checked against the whole input.
func awsSecretsInWindow(data []byte, left, right int, out []Finding) []Finding {
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
	return out
}

func awsSecretByte(b byte) bool { return ascii.IsAlphaNum(b) || b == '+' || b == '/' }
