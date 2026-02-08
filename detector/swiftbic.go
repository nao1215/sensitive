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

// SWIFTBIC detects SWIFT/BIC codes in text.
//
// SWIFT/BIC (Society for Worldwide Interbank Financial Telecommunication /
// Bank Identifier Code) is an 8- or 11-character identifier used for
// international wire transfers. The format is:
//
//	BBBBCCLL    (8 characters, head office)
//	BBBBCCLLBBB (11 characters, specific branch)
//
// Where:
//   - BBBB = bank/institution code (4 letters)
//   - CC   = ISO 3166-1 alpha-2 country code (2 letters)
//   - LL   = location code (2 alphanumeric characters)
//   - BBB  = branch code (3 alphanumeric characters, optional)
//
// Detection logic:
//  1. Scan for sequences of 8 or 11 alphanumeric characters
//  2. Validate the first 4 characters are alphabetic (bank code)
//  3. Validate characters 5-6 are a recognized ISO 3166-1 alpha-2 country code
//  4. Validate characters 7-8 are alphanumeric (location code)
//  5. If 11 characters, validate characters 9-11 are alphanumeric (branch code)
//  6. Both uppercase and lowercase inputs are accepted; letters are normalized
//     to uppercase for validation
//
// Confidence: 0.85 when format and country code are valid.
type SWIFTBIC struct{}

// NewSWIFTBIC creates a new SWIFT/BIC code detector.
func NewSWIFTBIC() *SWIFTBIC {
	return &SWIFTBIC{}
}

// Name returns "swiftbic".
func (d *SWIFTBIC) Name() DetectorName {
	return NameSWIFTBIC
}

// Hints returns nil, causing the Scanner to always run SWIFT/BIC detection.
// SWIFT/BIC codes have no common prefix or substring that can serve as an
// exhaustive hint. The 2-letter country code is too short and matches
// normal English text frequently. The Scan method itself performs fast
// rejection (4 alpha + valid country code) so the cost of always scanning
// is negligible.
func (d *SWIFTBIC) Hints() [][]byte {
	return nil
}

// Scan examines data for SWIFT/BIC codes and returns findings.
// Both uppercase and lowercase codes are detected. Letters are
// normalized to uppercase for country code validation.
func (d *SWIFTBIC) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-7; i++ {
		// First 4 characters must be alphabetic (bank code).
		if !isAlpha(data[i]) || !isAlpha(data[i+1]) || !isAlpha(data[i+2]) || !isAlpha(data[i+3]) {
			continue
		}

		// Characters 5-6 must be alphabetic (country code).
		if !isAlpha(data[i+4]) || !isAlpha(data[i+5]) {
			continue
		}

		// Characters 7-8 must be alphanumeric (location code).
		if !isAlphaNum(data[i+6]) || !isAlphaNum(data[i+7]) {
			continue
		}

		// Word boundary check: preceding character must not be alphanumeric.
		if i > 0 && isAlphaNum(data[i-1]) {
			continue
		}

		// Validate ISO 3166-1 alpha-2 country code.
		countryCode := string([]byte{toUpperByte(data[i+4]), toUpperByte(data[i+5])})
		if !swiftCountryCodes[countryCode] {
			continue
		}

		// Determine if this is an 8-char or 11-char SWIFT/BIC code.
		end := i + 8
		branchCode := ""

		if i+11 <= len(data) && isAlphaNum(data[i+8]) && isAlphaNum(data[i+9]) && isAlphaNum(data[i+10]) {
			// Potential 11-character code. Check that it doesn't continue further.
			if i+11 < len(data) && isAlphaNum(data[i+11]) {
				continue
			}
			end = i + 11
			branchCode = string([]byte{
				toUpperByte(data[i+8]),
				toUpperByte(data[i+9]),
				toUpperByte(data[i+10]),
			})
		} else if i+8 < len(data) && isAlphaNum(data[i+8]) {
			// 9 or 10 alphanumeric characters — not a valid SWIFT/BIC length.
			continue
		}

		// Exclude patterns that look like common English words or abbreviations.
		// SWIFT/BIC codes typically contain digits in the location or branch code.
		// Pure alpha codes of length 8 are common words; require at least one digit
		// in the location/branch portion OR the code must appear near SWIFT/BIC context.
		hasDigit := false
		for k := i + 6; k < end; k++ {
			if isDigit(data[k]) {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			// Pure alpha code: check for SWIFT/BIC context keywords nearby.
			if !hasSWIFTContext(data, i, end) {
				continue
			}
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
