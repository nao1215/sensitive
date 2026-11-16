package detect

import "bytes"

// SWIFTBICDetail holds SWIFT/BIC code-specific detail information.
type SWIFTBICDetail struct {
	// BankCode is the 4-letter bank/institution code (e.g., "DEUT" for Deutsche Bank).
	BankCode string
	// CountryCode is the ISO 3166-1 alpha-2 country code (e.g., "DE", "US", "GB").
	CountryCode string
	// LocationCode is the 2-character location code (alphanumeric).
	LocationCode string
	// BranchCode is the optional 3-character branch code (alphanumeric).
	// Empty string for 8-character SWIFT/BIC codes (head office).
	BranchCode string
}

// SWIFTBIC implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindSWIFTBIC.
type SWIFTBIC struct{}

// NewSWIFTBIC validates country and code shape without checking institution assignment.
func NewSWIFTBIC() *SWIFTBIC {
	return &SWIFTBIC{}
}

// Name returns "swiftbic".
func (d *SWIFTBIC) Name() DetectorName {
	return NameSWIFTBIC
}

// Hints returns nil because no selective exhaustive substring is available.
func (d *SWIFTBIC) Hints() [][]byte {
	return nil
}

// Scan returns matches in data using the rules documented on [SWIFTBIC].
func (d *SWIFTBIC) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-7; i++ {
		if !validateSWIFTStructure(data, i) {
			continue
		}

		end, branchCode, ok := determineSWIFTLength(data, i)
		if !ok || (entropyLocation(data, i, end) && !swiftSlashList(data, i, end)) {
			continue
		}

		// Pure alpha codes require nearby context keywords to avoid
		// false positives with common English words.
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if !hasDigitInRange(data, i+6, end) && !hasSWIFTContext(data, i, end) {
			continue
		}

		bankCode := string([]byte{
			toUpperByte(data[i]),
			toUpperByte(data[i+1]),
			toUpperByte(data[i+2]),
			toUpperByte(data[i+3]),
		})
		locationCode := string([]byte{
			toUpperByte(data[i+6]),
			toUpperByte(data[i+7]),
		})

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			//nolint:mnd // The detector contract documents this heuristic score.
			Confidence: 0.85,
			RawValue:   string(data[i:end]),
			Detail: &SWIFTBICDetail{
				BankCode:     bankCode,
				CountryCode:  string([]byte{toUpperByte(data[i+4]), toUpperByte(data[i+5])}),
				LocationCode: locationCode,
				BranchCode:   branchCode,
			},
		})

		i = end - 1
	}

	return findings
}

// A contextual slash-separated list can contain several bank identifiers.
// Requiring an adjacent complete code keeps ordinary source paths excluded.
func swiftSlashList(data []byte, start, end int) bool {
	if !hasSWIFTContext(data, start, end) {
		return false
	}
	codeEnd := func(at int) int {
		const shortCodeLength = 8
		if len(data)-at < shortCodeLength || !validateSWIFTStructure(data, at) {
			return -1
		}
		last, _, valid := determineSWIFTLength(data, at)
		if !valid {
			return -1
		}
		return last
	}
	if end < len(data) && data[end] == '/' && codeEnd(end+1) > 0 {
		return true
	}
	if start == 0 || data[start-1] != '/' {
		return false
	}
	previous := start - 1
	for previous > 0 && isAlphaNum(data[previous-1]) {
		previous--
	}
	return codeEnd(previous) == start-1
}

// validateSWIFTStructure checks the first 8 characters at data[i] for valid
// SWIFT/BIC structure: 4 alpha (bank) + 2 alpha (country) + 2 alphanumeric
// (location), with word boundary check and ISO country code validation.
func validateSWIFTStructure(data []byte, i int) bool {
	if !isAlpha(data[i]) || !isAlpha(data[i+1]) || !isAlpha(data[i+2]) || !isAlpha(data[i+3]) {
		return false
	}
	if !isAlpha(data[i+4]) || !isAlpha(data[i+5]) {
		return false
	}
	if !isAlphaNum(data[i+6]) || !isAlphaNum(data[i+7]) {
		return false
	}
	if i > 0 && isAlphaNum(data[i-1]) && !encodedSeparatorBefore(data, i) {
		return false
	}
	cc := [2]byte{toUpperByte(data[i+4]), toUpperByte(data[i+5])}
	return isSWIFTCountry(string(cc[:]))
}

// determineSWIFTLength determines whether the SWIFT/BIC code at data[i] is
// 8 or 11 characters. Returns (end, branchCode, true) for valid lengths,
// or (0, "", false) for invalid lengths (9 or 10 characters).
func determineSWIFTLength(data []byte, i int) (end int, branchCode string, ok bool) {
	if i+11 <= len(data) && isAlphaNum(data[i+8]) && isAlphaNum(data[i+9]) && isAlphaNum(data[i+10]) {
		if i+11 < len(data) && isAlphaNum(data[i+11]) {
			return 0, "", false
		}
		branch := string([]byte{
			toUpperByte(data[i+8]),
			toUpperByte(data[i+9]),
			toUpperByte(data[i+10]),
		})
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return i + 11, branch, true
	}
	if i+8 < len(data) && isAlphaNum(data[i+8]) {
		return 0, "", false
	}
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	return i + 8, "", true
}

// hasDigitInRange reports whether data[start:end] contains at least one digit.
func hasDigitInRange(data []byte, start, end int) bool {
	for k := start; k < end; k++ {
		if isDigit(data[k]) {
			return true
		}
	}
	return false
}

// hasSWIFTContext checks whether SWIFT/BIC context keywords appear near the
// candidate code. This is used to reduce false positives for pure-alpha codes
// (no digits in location/branch) that could be normal English words.
func hasSWIFTContext(data []byte, start, end int) bool {
	// Search within 50 bytes before and after the candidate.
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	searchStart := max(start-50, 0)
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	searchEnd := min(end+50, len(data))
	window := bytes.ToLower(data[searchStart:searchEnd])

	for _, kw := range swiftContextKeywords() {
		if bytes.Contains(window, kw) {
			return true
		}
	}
	return false
}

// swiftContextKeywords are lowercase keywords that indicate SWIFT/BIC context.
func swiftContextKeywords() [][]byte {
	return [][]byte{
		[]byte("swift"),
		[]byte("bic"),
		[]byte("bank identifier"),
		[]byte("wire"),
	}
}

// isSWIFTCountry checks the supported ISO 3166-1 alpha-2 country codes.
func isSWIFTCountry(code string) bool {
	switch code {
	case "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AR", "AS", "AT", "AU", "AW", "AX", "AZ":
		return true
	case "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BR", "BS":
		return true
	case "BT", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN":
		return true
	case "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC":
		return true
	case "EE", "EG", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE":
		return true
	case "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GT", "GU", "GW", "GY", "HK":
		return true
	case "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE":
		return true
	case "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA":
		return true
	case "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF":
		return true
	case "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW":
		return true
	case "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ":
		return true
	case "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY":
		return true
	case "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ":
		return true
	case "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF":
		return true
	case "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG":
		return true
	case "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "XK", "YE", "YT":
		return true
	case "ZA", "ZM", "ZW":
		return true
	default:
		return false
	}
}
