package detect

import (
	"bytes"
	"slices"
)

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

		end, ok := determineSWIFTLength(data, i)
		if !ok || (entropyLocation(data, i, end) && !swiftSlashList(data, i, end)) {
			continue
		}

		if registerSlot(data, i, end) {
			continue
		}

		if invalidUserSlot(data, i) {
			continue
		}

		if (i > 0 && data[i-1] == '_') || (end < len(data) && data[end] == '_') {
			continue
		}

		if hardwareWireSlot(data, i) {
			continue
		}

		// Pure alpha codes require nearby context keywords to avoid
		// false positives with common English words.
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if !hasDigitInRange(data, i+6, end) && !hasSWIFTContext(data, i, end) {
			continue
		}

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			//nolint:mnd // The detector contract documents this heuristic score.
			Confidence: 0.85,
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
		last, valid := determineSWIFTLength(data, at)
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
// 8 or 11 characters. Returns (end, true) for valid lengths,
// or (0, false) for invalid lengths (9 or 10 characters).
func determineSWIFTLength(data []byte, i int) (end int, ok bool) {
	if i+11 <= len(data) && isAlphaNum(data[i+8]) && isAlphaNum(data[i+9]) && isAlphaNum(data[i+10]) {
		if i+11 < len(data) && isAlphaNum(data[i+11]) {
			return 0, false
		}
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return i + 11, true
	}
	if i+8 < len(data) && isAlphaNum(data[i+8]) {
		return 0, false
	}
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	return i + 8, true
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
		for offset := 0; offset < len(window); {
			at := bytes.Index(window[offset:], kw)
			if at < 0 {
				break
			}
			at += offset
			after := at + len(kw)
			offset = after
			if at > 0 && isTokenByte(window[at-1]) {
				continue
			}
			if string(kw) == "swift" && after <= start-searchStart {
				if !swiftLabelGap(window[after : start-searchStart]) {
					continue
				}
			} else if after < len(window) && isTokenByte(window[after]) {
				continue
			}

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

// swiftLabelGap accepts ordinary field spellings without treating Swift build
// terminology as banking context. Case folding is owned by the caller.
func swiftLabelGap(gap []byte) bool {
	const separators = " \t\r\n_-/:=\"'.("
	list := bytes.ContainsRune(gap, '/')
	gap = bytes.Trim(gap, separators)
	// Earlier complete codes in a slash list share the same field label.
	for list && len(gap) >= 8 {
		end, ok := determineSWIFTLength(gap, 0)
		if !validateSWIFTStructure(gap, 0) || !ok {
			break
		}
		if end == len(gap) {
			return true
		}
		if gap[end] != '/' {
			break
		}
		gap = gap[end+1:]
	}
	if len(gap) == 0 {
		return true
	}
	return slices.Contains([]string{"code", "no", "number", "address", "bic"}, string(gap))
}
