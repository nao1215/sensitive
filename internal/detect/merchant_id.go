package detect

import "github.com/nao1215/embargo/internal/ascii"

// MerchantID implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindMerchantID.
type MerchantID struct {
	merchant nearRule
	terminal nearRule
}

// NewMerchantID selects merchant and terminal identifier grammars from nearby keywords.
func NewMerchantID() *MerchantID {
	//nolint:mnd // Literal field widths and scores follow the format rules documented on this detector.
	return &MerchantID{
		merchant: nearRule{keywords: merchantKeywords(), class: ascii.IsAlphaNum, accept: fixedConfidence(0.7), radius: 30, minLen: 15, maxLen: 15, overlap: true},
		terminal: nearRule{keywords: terminalKeywords(), class: ascii.IsDigit, accept: wholeTerminalToken, radius: 30, minLen: 8, maxLen: 8, overlap: true},
	}
}

// Name returns "merchant_id".
func (d *MerchantID) Name() DetectorName {
	return NameMerchantID
}

// Hints returns the pre-filter substrings for [MerchantID].
func (d *MerchantID) Hints() [][]byte {
	return [][]byte{
		[]byte("merchant"), // covers Merchant, MERCHANT, etc.
		[]byte("mid"),      // covers MID, Mid, mid
		[]byte("terminal"), // covers Terminal, TERMINAL, etc.
		[]byte("tid"),      // covers TID, Tid, tid
		// Japanese: 加盟店
		{0xE5, 0x8A, 0xA0, 0xE7, 0x9B, 0x9F, 0xE5, 0xBA, 0x97},
		// Japanese: 端末
		{0xE7, 0xAB, 0xAF, 0xE6, 0x9C, 0xAB},
	}
}

// Scan returns matches in data using the rules documented on [MerchantID].
// Terminal IDs never overlap an earlier merchant ID.
func (d *MerchantID) Scan(data []byte) []Finding {
	return d.terminal.scan(d.merchant.scan(nil, d.Name(), data, nil), d.Name(), data, nil)
}

// wholeTerminalToken accepts a terminal ID that is not embedded in a longer
// alphanumeric token, allowing an encoded separator before it. Masking only the
// digits of such a token would expose the rest of it.
func wholeTerminalToken(data []byte, seq digitSequence) (float64, bool) {
	//nolint:mnd // The score is documented on this detector.
	return 0.7, leadingBoundary(data, seq.start, ascii.IsAlphaNum) && trailingBoundary(data, seq.end, ascii.IsAlphaNum)
}

// merchantKeywords are context keywords for merchant ID detection.
func merchantKeywords() *keywordSet {
	return newKeywordSet([][]byte{
		[]byte("merchant ID"),
		[]byte("MID:"),
		[]byte("MID "),
		// Japanese: 加盟店ID
		append([]byte{0xE5, 0x8A, 0xA0, 0xE7, 0x9B, 0x9F, 0xE5, 0xBA, 0x97}, []byte("ID")...),
		// Japanese: 加盟店
		{0xE5, 0x8A, 0xA0, 0xE7, 0x9B, 0x9F, 0xE5, 0xBA, 0x97},
	})
}

// terminalKeywords are context keywords for terminal ID detection.
func terminalKeywords() *keywordSet {
	return newKeywordSet([][]byte{
		[]byte("terminal ID"),
		[]byte("TID:"),
		[]byte("TID "),
		// Japanese: 端末ID
		append([]byte{0xE7, 0xAB, 0xAF, 0xE6, 0x9C, 0xAB}, []byte("ID")...),
		// Japanese: 端末
		{0xE7, 0xAB, 0xAF, 0xE6, 0x9C, 0xAB},
	})
}
