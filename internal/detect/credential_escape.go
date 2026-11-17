package detect

import (
	"bytes"
	"cmp"
	"slices"
)

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
		mapping = ComposePositions(mapping, positions)
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

// Decode one quote/backslash escape layer. Positions
// map each decoded boundary to the original bytes, including escaped secrets.
func credentialQuotes(data []byte) (decoded []byte, positions []int) {
	if !bytes.Contains(data, []byte(`\"`)) && !bytes.Contains(data, []byte(`\\`)) && !bytes.Contains(data, []byte(`\x22`)) && !bytes.Contains(data, []byte(`\u0022`)) && !bytes.Contains(data, []byte(`\t`)) {
		return data, nil
	}
	decoded = make([]byte, 0, len(data))
	positions = make([]int, 0, len(data)+1)
	for i := 0; i < len(data); i++ {
		positions = append(positions, i)
		if hasASCIIPrefix(data, i, `\t`) {
			decoded = append(decoded, '\t')
			i++
			continue
		}
		if hasASCIIPrefix(data, i, `\x22`) {
			decoded = append(decoded, '"')
			i += 3
			continue
		}
		if hasASCIIPrefix(data, i, `\u0022`) {
			decoded = append(decoded, '"')
			i += 5
			continue
		}
		if data[i] == '\\' && i+1 < len(data) && (data[i+1] == '"' || data[i+1] == '\\') {
			i++
		}
		decoded = append(decoded, data[i])
	}
	positions = append(positions, len(data))
	return decoded, positions
}

// ScanViews adds normalized assignments while raw URL delimiters retain ownership
// of percent-escaped userinfo. Mapping always refers to original input bytes.
func (d *Credential) ScanViews(raw, normalized []byte, positions []int) []Finding {
	out := d.Scan(raw)
	if positions == nil {
		return out
	}
	previous, rawCount := 0, len(out)
	for _, f := range d.Scan(normalized) {
		f.Start, f.End = positions[f.Start], positions[f.End]
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
