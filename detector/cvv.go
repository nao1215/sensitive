package detector

// CVVDetail holds CVV/CVC-specific detail information.
type CVVDetail struct {
	// DigitCount is the number of digits in the detected CVV/CVC (3 or 4).
	// 3 digits: Visa, Mastercard, JCB, Discover.
	// 4 digits: American Express (CID).
	DigitCount int
}

// CVV detects card verification values (CVV/CVC/CID) in text.
//
// A CVV (Card Verification Value), CVC (Card Verification Code), or CID
// (Card Identification Number) is a 3- or 4-digit security code printed
// on payment cards. Because bare 3-4 digit numbers appear everywhere,
// this detector requires a context keyword to be present nearby.
//
// Detection logic:
//  1. Scan for context keywords: "CVV", "CVC", "CID", "CVV2", "CVC2",
//     "security code", "セキュリティコード" (and case variants)
//  2. Within a 30-byte radius of each keyword, look for a 3- or 4-digit
//     number that is not part of a longer digit sequence
//  3. Return the digit sequence as the finding (not the keyword)
//
// Confidence: 0.85 when a context keyword and valid digit sequence are found.
type CVV struct{}

// NewCVV creates a new CVV/CVC detector.
func NewCVV() *CVV {
	return &CVV{}
}

// Name returns "cvv".
func (d *CVV) Name() DetectorName {
	return NameCVV
}

// Hints returns byte sequences for pre-filtering.
// These keywords must appear in the input for CVV detection to trigger.
// The hints are exhaustive: without one of these keywords, a bare 3-4 digit
// number is not considered a CVV.
//
// ASCII hints are matched case-insensitively by Scanner's hint filter, so a
// single lowercase entry (e.g., "cvv") covers all case variants ("CVV",
// "Cvv", "SECURITY CODE", etc.). Non-ASCII hints (Japanese) are matched
// byte-for-byte.
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

// Scan examines data for CVV/CVC numbers near context keywords and returns findings.
func (d *CVV) Scan(data []byte) []Finding {
	matches := findKeywordPositions(data, cvvKeywords)
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
var cvvKeywords = [][]byte{
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
}
