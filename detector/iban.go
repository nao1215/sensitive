package detector

// IBANDetail holds IBAN-specific detail information.
type IBANDetail struct {
	// CountryCode is the ISO 3166-1 alpha-2 country code (e.g., "DE", "GB", "JP").
	CountryCode string
}

// IBAN detects International Bank Account Numbers in text.
//
// IBAN format: 2 letters (country code) + 2 digits (check digits)
// + up to 30 alphanumeric characters (BBAN).
// Both uppercase (DE89...) and lowercase (de89...) IBANs are detected;
// letters are normalized to uppercase internally for validation.
//
// Detection logic:
//  1. Scan for 2 ASCII letters (case-insensitive) followed by 2 digits
//  2. Validate the country code against known ISO 3166-1 alpha-2 codes
//  3. Verify the total length matches the expected length for that country
//  4. Validate the MOD 97 check digit (ISO 7064)
//
// Confidence: 0.95 when MOD 97 check passes.
type IBAN struct{}

// NewIBAN creates a new IBAN detector.
func NewIBAN() *IBAN {
	return &IBAN{}
}

// Name returns "iban".
func (d *IBAN) Name() DetectorName {
	return NameIBAN
}

// Hints returns nil, causing the Scanner to always run IBAN detection.
// Each supported country code is only 2 bytes long (e.g., "DE", "FR"),
// which frequently matches normal English text and triggers unnecessary
// scans. Returning nil avoids this overhead. The Scan method itself
// performs fast rejection (2 alpha + 2 digit check) so the cost of
// always scanning is negligible.
func (d *IBAN) Hints() [][]byte {
	return nil
}

// Scan examines data for IBANs and returns findings.
// Both uppercase and lowercase IBANs are detected. Letters are
// normalized to uppercase for country code lookup and MOD 97 validation.
func (d *IBAN) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-4; i++ {
		// IBAN starts with 2 letters (case-insensitive) + 2 digits.
		if !isAlpha(data[i]) || !isAlpha(data[i+1]) {
			continue
		}
		if !isDigit(data[i+2]) || !isDigit(data[i+3]) {
			continue
		}

		// Check that it's not part of a longer word.
		if i > 0 && isAlphaNum(data[i-1]) {
			continue
		}

		// Normalize country code to uppercase for lookup.
		countryCode := string([]byte{toUpperByte(data[i]), toUpperByte(data[i+1])})
		expectedLen, ok := ibanLengths[countryCode]
		if !ok {
			continue
		}

		start := i
		ibanChars, end := extractIBANChars(data, i)

		if len(ibanChars) != expectedLen {
			continue
		}

		// Check that the IBAN doesn't continue with alphanumeric chars.
		if end < len(data) && isAlphaNum(data[end]) {
			continue
		}

		if !validateIBANMod97(ibanChars) {
			continue
		}

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        start,
			End:          end,
			Confidence:   0.95,
			RawValue:     string(data[start:end]),
			Detail:       &IBANDetail{CountryCode: countryCode},
		})

		i = end - 1
	}

	return findings
}

// validateIBANMod97 validates an IBAN using the MOD 97 algorithm (ISO 7064).
// The IBAN is rearranged by moving the first 4 characters to the end,
// then converting letters to numbers (A=10, B=11, ..., Z=35) and checking
// that the resulting number mod 97 equals 1.
//
// Instead of constructing the full numeric string and using big.Int, this
// implementation uses streaming modular arithmetic:
//
//	For digits (one decimal place):  mod = (mod × 10 + digit) % 97
//	For letters A-Z (two decimal places, value 10-35): mod = (mod × 100 + value) % 97
//
// This avoids heap allocation and is significantly faster for bulk scanning.
func validateIBANMod97(iban []byte) bool {
	if len(iban) < 5 {
		return false
	}

	// Process in rearranged order: positions [4:] then [:4] (ISO 7064).
	mod := 0
	segments := [2][]byte{iban[4:], iban[:4]}
	for _, seg := range segments {
		for _, b := range seg {
			switch {
			case b >= '0' && b <= '9':
				mod = (mod*10 + int(b-'0')) % 97
			case b >= 'A' && b <= 'Z':
				mod = (mod*100 + int(b-'A') + 10) % 97
			default:
				return false
			}
		}
	}
	return mod == 1
}

// extractIBANChars extracts alphanumeric characters from data[start:],
// treating spaces as optional separators and normalizing to uppercase.
// Returns the extracted characters and the trimmed end position (excluding
// trailing spaces).
func extractIBANChars(data []byte, start int) (ibanChars []byte, end int) {
	j := start
	for j < len(data) && (isAlphaNum(data[j]) || data[j] == ' ') {
		if isAlphaNum(data[j]) {
			ibanChars = append(ibanChars, toUpperByte(data[j]))
		}
		j++
	}
	end = j
	for end > start && data[end-1] == ' ' {
		end--
	}
	return ibanChars, end
}

// toUpperByte converts an ASCII lowercase letter to uppercase.
// Non-lowercase bytes are returned unchanged.
func toUpperByte(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - 'a' + 'A'
	}
	return b
}

// ibanLengths maps country codes to their expected IBAN lengths.
// Source: https://www.swift.com/standards/data-standards/iban
var ibanLengths = map[string]int{
	"AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BY": 28,
	"BE": 16, "BA": 20, "BR": 29, "BG": 22, "CR": 22, "HR": 21,
	"CY": 28, "CZ": 24, "DK": 18, "DO": 28, "TL": 23, "EE": 20,
	"FO": 18, "FI": 18, "FR": 27, "GE": 22, "DE": 22, "GI": 23,
	"GR": 27, "GL": 18, "GT": 28, "HU": 28, "IS": 26, "IQ": 23,
	"IE": 22, "IL": 23, "IT": 27, "JO": 30, "KZ": 20, "XK": 20,
	"KW": 30, "LV": 21, "LB": 28, "LI": 21, "LT": 20, "LU": 20,
	"MK": 19, "MT": 31, "MR": 27, "MU": 30, "MC": 27, "MD": 24,
	"ME": 22, "NL": 18, "NO": 15, "PK": 24, "PS": 29, "PL": 28,
	"PT": 25, "QA": 29, "RO": 24, "SM": 27, "SA": 24, "RS": 22,
	"SK": 24, "SI": 19, "ES": 24, "SE": 24, "CH": 21, "TN": 24,
	"TR": 26, "UA": 29, "AE": 23, "GB": 22, "VA": 22, "VG": 24,
}
