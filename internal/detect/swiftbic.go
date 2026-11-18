package detect

import (
	"bytes"
	"slices"

	"github.com/nao1215/embargo/internal/ascii"
)

// SWIFTBIC implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindSWIFTBIC.
type SWIFTBIC struct {
	context [][]byte
}

// NewSWIFTBIC validates country and code shape without checking institution assignment.
func NewSWIFTBIC() *SWIFTBIC {
	return &SWIFTBIC{context: swiftContextKeywords()}
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
		if !ok || d.excluded(data, i, end) {
			continue
		}

		// Pure alpha codes require nearby context keywords to avoid
		// false positives with common English words.
		if !hasDigits(data[i+6:end], 1) && !d.hasContext(data, i, end) {
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

// excluded reports whether a structurally valid code at [i, end) is a
// token, register, user, identifier or hardware fragment rather than a BIC.
func (d *SWIFTBIC) excluded(data []byte, i, end int) bool {
	if uuidComponent(data, i, end) {
		return true
	}
	if entropyLocation(data, i, end) && !d.slashList(data, i, end) {
		return true
	}

	if registerSlot(data, i, end) {
		return true
	}

	if invalidUserSlot(data, i) {
		return true
	}

	if (i > 0 && data[i-1] == '_') || (end < len(data) && data[end] == '_') {
		return true
	}

	return hardwareWireSlot(data, i)
}

// A contextual slash-separated list can contain several bank identifiers.
// Requiring an adjacent complete code keeps ordinary source paths excluded.
func (d *SWIFTBIC) slashList(data []byte, start, end int) bool {
	if !d.hasContext(data, start, end) {
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
	for previous > 0 && ascii.IsAlphaNum(data[previous-1]) {
		previous--
	}
	return codeEnd(previous) == start-1
}

// validateSWIFTStructure checks the first 8 characters at data[i] for valid
// SWIFT/BIC structure: 4 alpha (bank) + 2 alpha (country) + 2 alphanumeric
// (location), with word boundary check and ISO country code validation.
func validateSWIFTStructure(data []byte, i int) bool {
	if !ascii.IsAlpha(data[i]) || !ascii.IsAlpha(data[i+1]) || !ascii.IsAlpha(data[i+2]) || !ascii.IsAlpha(data[i+3]) {
		return false
	}
	if !ascii.IsAlpha(data[i+4]) || !ascii.IsAlpha(data[i+5]) {
		return false
	}
	if !ascii.IsAlphaNum(data[i+6]) || !ascii.IsAlphaNum(data[i+7]) {
		return false
	}
	if !leadingBoundary(data, i, ascii.IsAlphaNum) {
		return false
	}
	cc := [2]byte{ascii.ToUpper(data[i+4]), ascii.ToUpper(data[i+5])}
	return isSWIFTCountry(string(cc[:]))
}

// determineSWIFTLength determines whether the SWIFT/BIC code at data[i] is
// 8 or 11 characters. Returns (end, true) for valid lengths,
// or (0, false) for invalid lengths (9 or 10 characters).
func determineSWIFTLength(data []byte, i int) (end int, ok bool) {
	if i+11 <= len(data) && ascii.IsAlphaNum(data[i+8]) && ascii.IsAlphaNum(data[i+9]) && ascii.IsAlphaNum(data[i+10]) {
		if i+11 < len(data) && ascii.IsAlphaNum(data[i+11]) {
			return 0, false
		}
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return i + 11, true
	}
	if i+8 < len(data) && ascii.IsAlphaNum(data[i+8]) {
		return 0, false
	}
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	return i + 8, true
}

// hasContext checks whether SWIFT/BIC context keywords appear near the
// candidate code. This is used to reduce false positives for pure-alpha codes
// (no digits in location/branch) that could be normal English words.
func (d *SWIFTBIC) hasContext(data []byte, start, end int) bool {
	// Search within 50 bytes before and after the candidate.
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	searchStart := max(start-50, 0)
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	searchEnd := min(end+50, len(data))
	// The window is at most 50+11+50 bytes, so it is lowered on the stack.
	var buf [128]byte
	window := ascii.AppendLower(buf[:0], data[searchStart:searchEnd])

	for _, kw := range d.context {
		if swiftKeywordInWindow(window, kw, start-searchStart) {
			return true
		}
	}
	return false
}

// swiftKeywordInWindow reports whether kw occurs in window as a whole token.
// "swift" before the candidate at codeStart may instead be followed by a label gap.
func swiftKeywordInWindow(window, kw []byte, codeStart int) bool {
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
		if string(kw) == "swift" && after <= codeStart {
			if !swiftLabelGap(window[after:codeStart]) {
				continue
			}
		} else if after < len(window) && isTokenByte(window[after]) {
			continue
		}

		return true
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
	return isSWIFTCountryADToLA(code) || isSWIFTCountryLBToZW(code)
}

// isSWIFTCountryADToLA checks the supported codes from AD through LA.
func isSWIFTCountryADToLA(code string) bool {
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
	default:
		return false
	}
}

// isSWIFTCountryLBToZW checks the supported codes from LB through ZW.
func isSWIFTCountryLBToZW(code string) bool {
	switch code {
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
