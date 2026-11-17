package detect

import "crypto/sha256"

// Base58Check decoding for legacy Bitcoin addresses.

// isBase58Char reports whether b is a valid Base58 character.
// The Base58 alphabet is: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
// It excludes: 0, I, O, l (to avoid visual ambiguity).
func isBase58Char(b byte) bool {
	return (b >= '1' && b <= '9') ||
		(b >= 'A' && b <= 'H') ||
		(b >= 'J' && b <= 'N') ||
		(b >= 'P' && b <= 'Z') ||
		(b >= 'a' && b <= 'k') ||
		(b >= 'm' && b <= 'z')
}

// base58Decode decodes a Base58-encoded string into raw bytes.
// Returns the decoded bytes and whether the decoding was successful.
//
// The algorithm processes each character as a digit in base-58 arithmetic,
// accumulating the result into a big-endian byte slice. Leading '1' characters
// in the input map to 0x00 bytes in the output (preserving leading zeros).
func base58Decode(s string) ([]byte, bool) {
	// Build result by multiplying by 58 and adding each digit.
	result := make([]byte, 0, len(s))

	for _, c := range []byte(s) {
		idx := base58CharIndex(c)
		if idx < 0 {
			return nil, false
		}

		carry := idx
		for j := range result {
			//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
			carry += int(result[j]) * 58
			//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
			result[j] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
			result = append(result, byte(carry&0xff))
			carry >>= 8
		}
	}

	// Count leading '1' chars (each represents a 0x00 byte).
	numLeadingZeros := 0
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		numLeadingZeros++
	}

	// Build final result: leading zeros + reversed accumulation.
	decoded := make([]byte, numLeadingZeros+len(result))
	// Leading zeros are already 0x00 (zero-value of byte slice).
	// Copy reversed result after the leading zeros.
	for i, j := numLeadingZeros, len(result)-1; j >= 0; i, j = i+1, j-1 {
		decoded[i] = result[j]
	}

	return decoded, true
}

// base58CharIndex returns the index of character c in the Base58 alphabet,
// or -1 if c is not a valid Base58 character.
func base58CharIndex(c byte) int {
	switch {
	case c >= '1' && c <= '9':
		return int(c - '1')
	case c >= 'A' && c <= 'H':
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return int(c-'A') + 9
	case c >= 'J' && c <= 'N':
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return int(c-'J') + 17
	case c >= 'P' && c <= 'Z':
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return int(c-'P') + 22
	case c >= 'a' && c <= 'k':
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return int(c-'a') + 33
	case c >= 'm' && c <= 'z':
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return int(c-'m') + 44
	default:
		return -1
	}
}

// validateBase58Checksum verifies the Base58Check checksum.
// The last 4 bytes of decoded must equal the first 4 bytes of
// SHA256(SHA256(payload)), where payload is decoded[:len(decoded)-4].
func validateBase58Checksum(decoded []byte) bool {
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(decoded) < 5 {
		return false
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])

	return h2[0] == checksum[0] &&
		h2[1] == checksum[1] &&
		h2[2] == checksum[2] &&
		h2[3] == checksum[3]
}
