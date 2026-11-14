package tests

// encodeWitness independently implements BIP-173/BIP-350's encoder; the
// production detector only decodes and validates addresses.
func encodeWitness(version byte, program []byte) string {
	const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	values := []byte{version}
	accumulator, bits := uint32(0), uint(0)
	for _, b := range program {
		accumulator = accumulator<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			values = append(values, byte(accumulator>>bits&31))
		}
	}
	if bits > 0 {
		values = append(values, byte(accumulator<<(5-bits)&31))
	}
	expanded := append([]byte{3, 3, 0, 2, 3}, values...)
	expanded = append(expanded, 0, 0, 0, 0, 0, 0)
	checksum := uint32(1)
	generators := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range expanded {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range generators {
			if top>>i&1 != 0 {
				checksum ^= g
			}
		}
	}
	if version == 0 {
		checksum ^= 1
	} else {
		checksum ^= 0x2bc830a3
	}
	result := []byte("bc1")
	for _, v := range values {
		result = append(result, alphabet[v])
	}
	for i := 5; i >= 0; i-- {
		result = append(result, alphabet[checksum>>uint(5*i)&31])
	}
	return string(result)
}
