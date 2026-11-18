package detect

import "github.com/nao1215/embargo/internal/ascii"

// CVV implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindCVV.
type CVV struct {
	rule nearRule
}

// NewCVV requires card-verification context around three or four digits.
func NewCVV() *CVV {
	//nolint:mnd // Literal field widths and the score follow the format rules documented on this detector.
	return &CVV{rule: nearRule{keywords: cvvKeywords(), class: ascii.IsDigit, accept: fixedConfidence(0.85), radius: 30, minLen: 3, maxLen: 4}}
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
	return d.rule.scan(nil, d.Name(), data, nil)
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
		[]byte("security code"),
		// Japanese: セキュリティコード
		{
			0xE3, 0x82, 0xBB, 0xE3, 0x82, 0xAD, 0xE3, 0x83, 0xA5, 0xE3,
			0x83, 0xAA, 0xE3, 0x83, 0x86, 0xE3, 0x82, 0xA3, 0xE3, 0x82,
			0xB3, 0xE3, 0x83, 0xBC, 0xE3, 0x83, 0x89,
		},
	})
}
