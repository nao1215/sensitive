package embargo

import "bytes"

// decodePercent decodes one layer of valid %HH escapes, preserving '+' and invalid
// escapes. A nil map denotes identity; otherwise it includes the end sentinel.
func decodePercent(data []byte) (decoded []byte, positions []int) {
	first := bytes.IndexByte(data, '%')
	if first < 0 {
		return data, nil
	}
	for i := first; i+2 < len(data); i++ {
		if data[i] != '%' {
			continue
		}
		hi, ok := percentHex(data[i+1])
		lo, ok2 := percentHex(data[i+2])
		if !ok || !ok2 {
			continue
		}
		if decoded == nil {
			decoded = make([]byte, 0, len(data))
			decoded = append(decoded, data[:i]...)
			// The first escape removes two bytes, leaving room for the sentinel
			// within len(data) and avoiding overflow from adding capacity.
			positions = make([]int, i, len(data))
			for j := range positions {
				positions[j] = j
			}
		}
		decoded = append(decoded, hi<<4|lo)
		positions = append(positions, i)
		i += 3
		for i < len(data) {
			if data[i] == '%' && i+2 < len(data) {
				_, ok = percentHex(data[i+1])
				_, ok2 = percentHex(data[i+2])
				if ok && ok2 {
					break
				}
			}
			decoded = append(decoded, data[i])
			positions = append(positions, i)
			i++
		}
		i--
	}
	if decoded == nil {
		return data, nil
	}
	positions = append(positions, len(data))
	return decoded, positions
}

//nolint:mnd // Hexadecimal digit values.
func percentHex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}
