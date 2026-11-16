package detect

// MerchantIDType represents the type of merchant/terminal identifier detected.
type MerchantIDType string

const (
	// MerchantIDTypeMerchant indicates a merchant ID (MID).
	MerchantIDTypeMerchant MerchantIDType = "merchant"
	// MerchantIDTypeTerminal indicates a terminal ID (TID).
	MerchantIDTypeTerminal MerchantIDType = "terminal"
)

// MerchantIDDetail holds merchant/terminal ID-specific detail information.
type MerchantIDDetail struct {
	// IDType is the type of identifier detected.
	IDType MerchantIDType
}

// MerchantID implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindMerchantID.
type MerchantID struct {
	merchantKeywords *keywordSet
	terminalKeywords *keywordSet
}

// NewMerchantID selects merchant and terminal identifier grammars from nearby keywords.
func NewMerchantID() *MerchantID {
	return &MerchantID{merchantKeywords: merchantKeywords(), terminalKeywords: terminalKeywords()}
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
func (d *MerchantID) Scan(data []byte) []Finding {
	var findings []Finding

	// Check merchant keywords.
	merchantMatches := d.merchantKeywords.findPositions(data)
	for _, m := range merchantMatches {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		seqs := extractAlphaNumNear(data, m.end, 30, 15, 15)
		for _, seq := range seqs {
			if overlapsFinding(findings, seq.start, seq.end) {
				continue
			}
			if seq.start < m.end && seq.end > m.start {
				continue
			}

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        seq.start,
				End:          seq.end,
				//nolint:mnd // The detector contract documents this heuristic score.
				Confidence: 0.7,
				RawValue:   string(data[seq.start:seq.end]),
				Detail:     &MerchantIDDetail{IDType: MerchantIDTypeMerchant},
			})
		}
	}

	// Check terminal keywords.
	terminalMatches := d.terminalKeywords.findPositions(data)
	for _, m := range terminalMatches {
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		seqs := extractDigitsNear(data, m.end, 30, 8, 8)
		for _, seq := range seqs {
			if overlapsFinding(findings, seq.start, seq.end) {
				continue
			}
			if seq.start < m.end && seq.end > m.start {
				continue
			}

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        seq.start,
				End:          seq.end,
				//nolint:mnd // The detector contract documents this heuristic score.
				Confidence: 0.7,
				RawValue:   string(data[seq.start:seq.end]),
				Detail:     &MerchantIDDetail{IDType: MerchantIDTypeTerminal},
			})
		}
	}

	return findings
}

// overlapsFinding reports whether [start, end) overlaps any existing finding.
// A digit run inside an already reported merchant ID (e.g., "00000000" in
// "A00000000A00000") must not be reported again as a terminal ID.
func overlapsFinding(findings []Finding, start, end int) bool {
	for _, f := range findings {
		if start < f.End && end > f.Start {
			return true
		}
	}
	return false
}

// merchantKeywords are context keywords for merchant ID detection.
func merchantKeywords() *keywordSet {
	return newKeywordSet([][]byte{
		[]byte("merchant ID"),
		[]byte("Merchant ID"),
		[]byte("MERCHANT ID"),
		[]byte("merchant id"),
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
		[]byte("Terminal ID"),
		[]byte("TERMINAL ID"),
		[]byte("terminal id"),
		[]byte("TID:"),
		[]byte("TID "),
		// Japanese: 端末ID
		append([]byte{0xE7, 0xAB, 0xAF, 0xE6, 0x9C, 0xAB}, []byte("ID")...),
		// Japanese: 端末
		{0xE7, 0xAB, 0xAF, 0xE6, 0x9C, 0xAB},
	})
}
