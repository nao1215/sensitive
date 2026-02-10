package detector

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

// MerchantID detects merchant IDs (MIDs) and terminal IDs (TIDs) in text.
//
// A Merchant ID (MID) is a unique identifier assigned to a merchant by a
// payment processor, typically 15 alphanumeric characters. A Terminal ID (TID)
// identifies a specific payment terminal, typically 8 alphanumeric characters.
//
// Because these patterns are generic (15 or 8 alphanumeric characters), this
// detector requires a context keyword to be present nearby.
//
// Detection logic:
//  1. Scan for context keywords:
//     English: "merchant ID", "MID", "terminal ID", "TID"
//     Japanese: "加盟店", "端末"
//  2. Within a 30-byte radius of each keyword, look for:
//     - Merchant ID: 15 alphanumeric characters
//     - Terminal ID: 8 alphanumeric characters (digits only for TID)
//  3. Determine the ID type based on the matched keyword
//
// Confidence: 0.7 when a context keyword and valid identifier are found.
type MerchantID struct{}

// NewMerchantID creates a new merchant/terminal ID detector.
func NewMerchantID() *MerchantID {
	return &MerchantID{}
}

// Name returns "merchant_id".
func (d *MerchantID) Name() DetectorName {
	return NameMerchantID
}

// Hints returns byte sequences for pre-filtering.
// These keywords must appear in the input for merchant/terminal ID detection.
//
// ASCII hints are matched case-insensitively by Scanner's hint filter, so a
// single lowercase entry (e.g., "merchant") covers all case variants
// ("Merchant", "MERCHANT", etc.). Non-ASCII hints (Japanese) are matched
// byte-for-byte.
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

// Scan examines data for merchant/terminal IDs near context keywords and returns findings.
func (d *MerchantID) Scan(data []byte) []Finding {
	var findings []Finding
	used := make(map[int]struct{})

	// Check merchant keywords.
	merchantMatches := merchantKeywords.findPositions(data)
	for _, m := range merchantMatches {
		seqs := extractAlphaNumNear(data, m.end, 30, 15, 15)
		for _, seq := range seqs {
			if _, ok := used[seq.start]; ok {
				continue
			}
			if seq.start < m.end && seq.end > m.start {
				continue
			}
			used[seq.start] = struct{}{}

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        seq.start,
				End:          seq.end,
				Confidence:   0.7,
				RawValue:     string(data[seq.start:seq.end]),
				Detail:       &MerchantIDDetail{IDType: MerchantIDTypeMerchant},
			})
		}
	}

	// Check terminal keywords.
	terminalMatches := terminalKeywords.findPositions(data)
	for _, m := range terminalMatches {
		seqs := extractDigitsNear(data, m.end, 30, 8, 8)
		for _, seq := range seqs {
			if _, ok := used[seq.start]; ok {
				continue
			}
			if seq.start < m.end && seq.end > m.start {
				continue
			}
			used[seq.start] = struct{}{}

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        seq.start,
				End:          seq.end,
				Confidence:   0.7,
				RawValue:     string(data[seq.start:seq.end]),
				Detail:       &MerchantIDDetail{IDType: MerchantIDTypeTerminal},
			})
		}
	}

	return findings
}

// merchantKeywords are context keywords for merchant ID detection.
var merchantKeywords = newKeywordSet([][]byte{
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

// terminalKeywords are context keywords for terminal ID detection.
var terminalKeywords = newKeywordSet([][]byte{
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
