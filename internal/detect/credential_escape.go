package detect

import (
	"bytes"
)

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
