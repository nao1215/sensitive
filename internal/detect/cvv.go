package detect

// CVV implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindCVV.
type CVV struct {
	cvvKeywords *keywordSet
}

// NewCVV requires card-verification context around three or four digits.
func NewCVV() *CVV {
	return &CVV{cvvKeywords: cvvKeywords()}
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
		{
			0xE3, 0x82, 0xBB, 0xE3, 0x82, 0xAD, 0xE3, 0x83, 0xA5, 0xE3,
			0x83, 0xAA, 0xE3, 0x83, 0x86, 0xE3, 0x82, 0xA3, 0xE3, 0x82,
			0xB3, 0xE3, 0x83, 0xBC, 0xE3, 0x83, 0x89,
		},
	}
}

// Scan returns matches in data using the rules documented on [CVV].
func (d *CVV) Scan(data []byte) []Finding {
	matches := d.cvvKeywords.findPositions(data)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding
	used := make(map[int]struct{}) // track digit sequence start positions already reported

	for _, m := range matches {
		// Search for digit sequences near the keyword.
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		seqs := extractDigitsNear(data, m.end, 30, 3, 4)
		for _, seq := range seqs {
			if _, ok := used[seq.start]; ok {
				continue
			}

			used[seq.start] = struct{}{}

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        seq.start,
				End:          seq.end,
				//nolint:mnd // The detector contract documents this heuristic score.
				Confidence: 0.85,
			})
		}
	}

	return findings
}

// cvvKeywords are the context keywords used to identify CVV/CVC/CID mentions.
// CID (Card Identification Number) is the 4-digit security code used by
// American Express. It is functionally equivalent to CVV/CVC on other networks.
func cvvKeywords() *keywordSet {
	return newKeywordSet([][]byte{
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
		{
			0xE3, 0x82, 0xBB, 0xE3, 0x82, 0xAD, 0xE3, 0x83, 0xA5, 0xE3,
			0x83, 0xAA, 0xE3, 0x83, 0x86, 0xE3, 0x82, 0xA3, 0xE3, 0x82,
			0xB3, 0xE3, 0x83, 0xBC, 0xE3, 0x83, 0x89,
		},
	})
}
