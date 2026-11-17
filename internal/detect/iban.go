package detect

import "github.com/nao1215/embargo/internal/ascii"

// IBAN implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindIBAN.
type IBAN struct{}

// NewIBAN combines country lengths with MOD 97 validation.
func NewIBAN() *IBAN {
	return &IBAN{}
}

// Name returns "iban".
func (d *IBAN) Name() DetectorName {
	return NameIBAN
}

// Hints returns nil because no selective exhaustive substring is available.
func (d *IBAN) Hints() [][]byte {
	return nil
}

// Scan returns matches in data using the rules documented on [IBAN].
func (d *IBAN) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data)-4; i++ {
		if !ibanPrefixAt(data, i) {
			continue
		}

		// Normalize country code to uppercase for lookup.
		countryCode := string([]byte{ascii.ToUpper(data[i]), ascii.ToUpper(data[i+1])})
		expectedLen, ok := ibanCountryLength(countryCode)
		if !ok {
			continue
		}

		start := i
		ibanChars, end := extractIBANChars(data, i, expectedLen)

		if len(ibanChars) != expectedLen {
			continue
		}

		// Check that the IBAN doesn't continue with alphanumeric chars.
		if end < len(data) && ascii.IsAlphaNum(data[end]) {
			continue
		}

		if !validateIBANMod97(ibanChars) {
			continue
		}

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        start,
			End:          end,
			//nolint:mnd // The detector contract documents this heuristic score.
			Confidence: 0.95,
		})

		i = end - 1
	}

	return findings
}

// ibanPrefixAt reports whether an IBAN prefix of two letters and two check
// digits starts a word at i.
func ibanPrefixAt(data []byte, i int) bool {
	// IBAN starts with 2 letters (case-insensitive) + 2 digits.
	if !ascii.IsAlpha(data[i]) || !ascii.IsAlpha(data[i+1]) {
		return false
	}
	if !ascii.IsDigit(data[i+2]) || !ascii.IsDigit(data[i+3]) {
		return false
	}

	// Check that it's not part of a longer word.
	return i == 0 || !ascii.IsAlphaNum(data[i-1]) || encodedSeparatorBefore(data, i)
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
	if len(iban) < 5 || (iban[2] == '0' && iban[3] < '2') || (iban[2] == '9' && iban[3] == '9') {
		return false
	}

	// Process in rearranged order: positions [4:] then [:4] (ISO 7064).
	mod := 0
	segments := [2][]byte{iban[4:], iban[:4]}
	for _, seg := range segments {
		for _, b := range seg {
			switch {
			case ascii.IsDigit(b):
				//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
				mod = (mod*10 + int(b-'0')) % 97
			case ascii.IsUpper(b):
				//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
// trailing spaces). Extraction stops at the country-specific length so a
// following word cannot become part of the checksum candidate.
func extractIBANChars(data []byte, start, expectedLen int) (ibanChars []byte, end int) {
	j := start
	for j < len(data) && len(ibanChars) < expectedLen && (ascii.IsAlphaNum(data[j]) || data[j] == ' ') {
		if ascii.IsAlphaNum(data[j]) {
			ibanChars = append(ibanChars, ascii.ToUpper(data[j]))
		}
		j++
	}
	end = j
	for end > start && data[end-1] == ' ' {
		end--
	}
	return ibanChars, end
}

// ibanCountryLength returns the country length from SWIFT IBAN Registry release
// 103 (September 2026): https://www.swift.com/swift-resource/9606/download .
// A switch keeps the registry immutable without package-level state.
func ibanCountryLength(country string) (int, bool) {
	if n, ok := ibanShortCountryLength(country); ok {
		return n, true
	}
	return ibanLongCountryLength(country)
}

// ibanShortCountryLength returns registry lengths of 15 to 24 characters.
func ibanShortCountryLength(country string) (int, bool) {
	switch country {
	case "NO":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 15, true
	case "BE":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 16, true
	case "DK", "FI", "FK", "FO", "GL", "NL", "SD":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 18, true
	case "MK", "SI":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 19, true
	case "AT", "BA", "EE", "KZ", "LT", "LU", "MN", "XK":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 20, true
	case "CH", "HR", "LI", "LV":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 21, true
	case "BG", "BH", "CR", "DE", "GB", "GE", "IE", "ME", "RS", "VA":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 22, true
	case "AE", "GI", "IL", "IQ", "OM", "SO", "TL":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 23, true
	case "AD", "CZ", "ES", "MD", "PK", "RO", "SA", "SE", "SK", "TN", "VG":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 24, true
	default:
		return 0, false
	}
}

// ibanLongCountryLength returns registry lengths of 25 to 33 characters.
func ibanLongCountryLength(country string) (int, bool) {
	switch country {
	case "LY", "PT", "ST":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 25, true
	case "IS", "TR":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 26, true
	case "BI", "DJ", "FR", "GR", "IT", "MC", "MR", "SM":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 27, true
	case "AL", "AZ", "BY", "CY", "DO", "GT", "HN", "HU", "LB", "NI", "PL", "SV":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 28, true
	case "BR", "EG", "PS", "QA", "UA":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 29, true
	case "JO", "KW", "MU", "YE":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 30, true
	case "MT", "SC":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 31, true
	case "LC":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 32, true
	case "RU":
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return 33, true
	default:
		return 0, false
	}
}
