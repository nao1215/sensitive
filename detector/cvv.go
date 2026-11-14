package detector

// CVVDetail holds CVV/CVC-specific detail information.
type CVVDetail struct {
	// DigitCount is 3 for CVV/CVC or 4 for American Express CID.
	DigitCount int
}

// CVV detects card verification values from nearby keywords, without checksum validation.
//
//  1. Find CVV, CVC, CID, CVV2, CVC2, security code, or セキュリティコード (ASCII case-insensitive).
//  2. Search within 30 bytes of the keyword end for a separate three- or four-digit sequence that does not overlap the keyword.
//  3. Return only the digits with confidence 0.85.
type CVV struct{}

// NewCVV creates a new CVV/CVC detector.
func NewCVV() *CVV {
	return &CVV{}
}

// Name returns "cvv".
func (d *CVV) Name() DetectorName {
	return NameCVV
}

// Hints returns the pre-filter substrings for [CVV].
func (d *CVV) Hints() [][]byte {
	return [][]byte{
		[]byte("cvv"),           // covers CVV, Cvv, CVV2, cvv2, etc.
		[]byte("cvc"),           // covers CVC, Cvc, CVC2, cvc2, etc.
		[]byte("cid"),           // covers CID, Cid, cid
		[]byte("security code"), // covers SECURITY CODE, Security Code, etc.
		// Japanese: セキュリティコード
		{0xE3, 0x82, 0xBB, 0xE3, 0x82, 0xAD, 0xE3, 0x83, 0xA5, 0xE3,
			0x83, 0xAA, 0xE3, 0x83, 0x86, 0xE3, 0x82, 0xA3, 0xE3, 0x82,
			0xB3, 0xE3, 0x83, 0xBC, 0xE3, 0x83, 0x89},
	}
}

// Scan returns matches in data using the rules documented on [CVV].
func (d *CVV) Scan(data []byte) []Finding {
	matches := cvvKeywords.findPositions(data)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding
	used := make(map[int]struct{}) // track digit sequence start positions already reported

	for _, m := range matches {
		// Search for digit sequences near the keyword.
		seqs := extractDigitsNear(data, m.end, 30, 3, 4)
		for _, seq := range seqs {
			if _, ok := used[seq.start]; ok {
				continue
			}

			// Ensure the digit sequence doesn't overlap with the keyword.
			if seq.start < m.end && seq.end > m.start {
				continue
			}

			used[seq.start] = struct{}{}
			digitCount := seq.end - seq.start

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        seq.start,
				End:          seq.end,
				Confidence:   0.85,
				RawValue:     string(data[seq.start:seq.end]),
				Detail:       &CVVDetail{DigitCount: digitCount},
			})
		}
	}

	return findings
}

// cvvKeywords are the context keywords used to identify CVV/CVC/CID mentions.
// CID (Card Identification Number) is the 4-digit security code used by
// American Express. It is functionally equivalent to CVV/CVC on other networks.
var cvvKeywords = newKeywordSet([][]byte{
	[]byte("CVV2"),
	[]byte("CVC2"),
	[]byte("CVV"),
	[]byte("CVC"),
	[]byte("CID"),
	[]byte("cvv2"),
	[]byte("cvc2"),
	[]byte("cvv"),
	[]byte("cvc"),
	[]byte("cid"),
	[]byte("Cvv"),
	[]byte("Cvc"),
	[]byte("Cid"),
	[]byte("security code"),
	[]byte("Security Code"),
	[]byte("Security code"),
	[]byte("SECURITY CODE"),
	// Japanese: セキュリティコード
	{0xE3, 0x82, 0xBB, 0xE3, 0x82, 0xAD, 0xE3, 0x83, 0xA5, 0xE3,
		0x83, 0xAA, 0xE3, 0x83, 0x86, 0xE3, 0x82, 0xA3, 0xE3, 0x82,
		0xB3, 0xE3, 0x83, 0xBC, 0xE3, 0x83, 0x89},
})
