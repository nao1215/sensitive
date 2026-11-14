package detector

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

// SWIFTBIC detects 8- or 11-character bank identifiers for international wire transfers, without checking assignment to an institution.
//
//  1. Extract an alphanumeric candidate and uppercase letters for validation.
//  2. Require four bank letters, a recognized two-letter ISO 3166-1 country code, two alphanumeric location characters, and optionally three alphanumeric branch characters.
//  3. Score a match as 0.85; an absent branch denotes the head office.
type SWIFTBIC struct{}

// NewSWIFTBIC creates a new SWIFT/BIC code detector.
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
		countryCode, ok := validateSWIFTStructure(data, i)
		if !ok {
			continue
		}

		end, branchCode, ok := determineSWIFTLength(data, i)
		if !ok {
			continue
		}

		// Pure alpha codes require nearby context keywords to avoid
		// false positives with common English words.
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
			Confidence:   0.85,
			RawValue:     string(data[i:end]),
			Detail: &SWIFTBICDetail{
				BankCode:     bankCode,
				CountryCode:  countryCode,
				LocationCode: locationCode,
				BranchCode:   branchCode,
			},
		})

		i = end - 1
	}

	return findings
}

// validateSWIFTStructure checks the first 8 characters at data[i] for valid
// SWIFT/BIC structure: 4 alpha (bank) + 2 alpha (country) + 2 alphanumeric
// (location), with word boundary check and ISO country code validation.
func validateSWIFTStructure(data []byte, i int) (countryCode string, ok bool) {
	if !isAlpha(data[i]) || !isAlpha(data[i+1]) || !isAlpha(data[i+2]) || !isAlpha(data[i+3]) {
		return "", false
	}
	if !isAlpha(data[i+4]) || !isAlpha(data[i+5]) {
		return "", false
	}
	if !isAlphaNum(data[i+6]) || !isAlphaNum(data[i+7]) {
		return "", false
	}
	if i > 0 && isAlphaNum(data[i-1]) && !encodedSeparatorBefore(data, i) {
		return "", false
	}
	cc := string([]byte{toUpperByte(data[i+4]), toUpperByte(data[i+5])})
	if !swiftCountryCodes[cc] {
		return "", false
	}
	return cc, true
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
		return i + 11, branch, true
	}
	if i+8 < len(data) && isAlphaNum(data[i+8]) {
		return 0, "", false
	}
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
	searchStart := start - 50
	if searchStart < 0 {
		searchStart = 0
	}
	searchEnd := end + 50
	if searchEnd > len(data) {
		searchEnd = len(data)
	}
	window := bytes.ToLower(data[searchStart:searchEnd])

	for _, kw := range swiftContextKeywords {
		if bytes.Contains(window, kw) {
			return true
		}
	}
	return false
}

// swiftContextKeywords are lowercase keywords that indicate SWIFT/BIC context.
var swiftContextKeywords = [][]byte{
	[]byte("swift"),
	[]byte("bic"),
	[]byte("bank identifier"),
	[]byte("wire"),
}

// swiftCountryCodes is the set of ISO 3166-1 alpha-2 country codes used for
// SWIFT/BIC country code validation.
// Source: https://www.iso.org/iso-3166-country-codes.html
var swiftCountryCodes = map[string]bool{
	"AD": true, "AE": true, "AF": true, "AG": true, "AI": true,
	"AL": true, "AM": true, "AO": true, "AR": true, "AS": true,
	"AT": true, "AU": true, "AW": true, "AX": true, "AZ": true,
	"BA": true, "BB": true, "BD": true, "BE": true, "BF": true,
	"BG": true, "BH": true, "BI": true, "BJ": true, "BL": true,
	"BM": true, "BN": true, "BO": true, "BR": true, "BS": true,
	"BT": true, "BW": true, "BY": true, "BZ": true,
	"CA": true, "CC": true, "CD": true, "CF": true, "CG": true,
	"CH": true, "CI": true, "CK": true, "CL": true, "CM": true,
	"CN": true, "CO": true, "CR": true, "CU": true, "CV": true,
	"CW": true, "CX": true, "CY": true, "CZ": true,
	"DE": true, "DJ": true, "DK": true, "DM": true, "DO": true,
	"DZ": true,
	"EC": true, "EE": true, "EG": true, "ER": true, "ES": true,
	"ET": true,
	"FI": true, "FJ": true, "FK": true, "FM": true, "FO": true,
	"FR": true,
	"GA": true, "GB": true, "GD": true, "GE": true, "GF": true,
	"GG": true, "GH": true, "GI": true, "GL": true, "GM": true,
	"GN": true, "GP": true, "GQ": true, "GR": true, "GT": true,
	"GU": true, "GW": true, "GY": true,
	"HK": true, "HN": true, "HR": true, "HT": true, "HU": true,
	"ID": true, "IE": true, "IL": true, "IM": true, "IN": true,
	"IO": true, "IQ": true, "IR": true, "IS": true, "IT": true,
	"JE": true, "JM": true, "JO": true, "JP": true,
	"KE": true, "KG": true, "KH": true, "KI": true, "KM": true,
	"KN": true, "KP": true, "KR": true, "KW": true, "KY": true,
	"KZ": true,
	"LA": true, "LB": true, "LC": true, "LI": true, "LK": true,
	"LR": true, "LS": true, "LT": true, "LU": true, "LV": true,
	"LY": true,
	"MA": true, "MC": true, "MD": true, "ME": true, "MF": true,
	"MG": true, "MH": true, "MK": true, "ML": true, "MM": true,
	"MN": true, "MO": true, "MP": true, "MQ": true, "MR": true,
	"MS": true, "MT": true, "MU": true, "MV": true, "MW": true,
	"MX": true, "MY": true, "MZ": true,
	"NA": true, "NC": true, "NE": true, "NF": true, "NG": true,
	"NI": true, "NL": true, "NO": true, "NP": true, "NR": true,
	"NU": true, "NZ": true,
	"OM": true,
	"PA": true, "PE": true, "PF": true, "PG": true, "PH": true,
	"PK": true, "PL": true, "PM": true, "PN": true, "PR": true,
	"PS": true, "PT": true, "PW": true, "PY": true,
	"QA": true,
	"RE": true, "RO": true, "RS": true, "RU": true, "RW": true,
	"SA": true, "SB": true, "SC": true, "SD": true, "SE": true,
	"SG": true, "SH": true, "SI": true, "SJ": true, "SK": true,
	"SL": true, "SM": true, "SN": true, "SO": true, "SR": true,
	"SS": true, "ST": true, "SV": true, "SX": true, "SY": true,
	"SZ": true,
	"TC": true, "TD": true, "TF": true, "TG": true, "TH": true,
	"TJ": true, "TK": true, "TL": true, "TM": true, "TN": true,
	"TO": true, "TR": true, "TT": true, "TV": true, "TW": true,
	"TZ": true,
	"UA": true, "UG": true, "US": true, "UY": true, "UZ": true,
	"VA": true, "VC": true, "VE": true, "VG": true, "VI": true,
	"VN": true, "VU": true,
	"WF": true, "WS": true,
	"XK": true,
	"YE": true, "YT": true,
	"ZA": true, "ZM": true, "ZW": true,
}
