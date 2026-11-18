package detect

// JPPhoneType classifies a Japanese phone number; see the JPPhoneType* constants.
type JPPhoneType string

const (
	// JPPhoneTypeMobile identifies mobile phone numbers (090, 080, 070 prefix).
	JPPhoneTypeMobile JPPhoneType = "mobile"
	// JPPhoneTypeLandline identifies landline phone numbers.
	JPPhoneTypeLandline JPPhoneType = "landline"
	// JPPhoneTypeIPPhone identifies IP phone numbers (050 prefix).
	JPPhoneTypeIPPhone JPPhoneType = "ip_phone"
	// JPPhoneTypeTollFree identifies toll-free numbers (0120, 0800 prefix).
	JPPhoneTypeTollFree JPPhoneType = "toll_free"
	// JPPhoneTypeM2M identifies M2M/IoT numbers (020 prefix, 11 digits).
	JPPhoneTypeM2M JPPhoneType = "m2m"
	// JPPhoneTypeService identifies FMC/unified service numbers (060 prefix, 11 digits).
	JPPhoneTypeService JPPhoneType = "service"
)

// jpPhoneRule defines a prefix-based classification rule for Japanese phone numbers.
// Each rule matches a specific digit length and a prefix (starting at digits[1])
// to produce a JPPhoneType.
type jpPhoneRule struct {
	prefix   string
	result   JPPhoneType
	digitLen int
}

// jpPhoneRules is the table of prefix-based classification rules for Japanese
// phone numbers. Rules are evaluated in order; the first match wins.
func jpPhoneRules() []jpPhoneRule {
	return []jpPhoneRule{
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{digitLen: 11, prefix: "90", result: JPPhoneTypeMobile},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{digitLen: 11, prefix: "80", result: JPPhoneTypeMobile},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{digitLen: 11, prefix: "70", result: JPPhoneTypeMobile},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{digitLen: 11, prefix: "50", result: JPPhoneTypeIPPhone},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{digitLen: 11, prefix: "20", result: JPPhoneTypeM2M},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{digitLen: 11, prefix: "60", result: JPPhoneTypeService},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{digitLen: 10, prefix: "120", result: JPPhoneTypeTollFree},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{digitLen: 11, prefix: "800", result: JPPhoneTypeTollFree},
	}
}

// JPPhone implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindJPPhone.
type JPPhone struct{}

// NewJPPhone combines supported Japanese prefixes with ten- or eleven-digit lengths.
func NewJPPhone() *JPPhone {
	return &JPPhone{}
}

// Name returns "phone_jp".
func (d *JPPhone) Name() DetectorName {
	return NameJPPhone
}

// Hints returns the pre-filter substrings for [JPPhone].
func (d *JPPhone) Hints() [][]byte {
	return [][]byte{
		[]byte("0"),
		{0xEF, 0xBC, 0x90}, // ０ full-width zero (U+FF10)
		[]byte("+81"),
	}
}

// Scan returns matches in data using the rules documented on [JPPhone].
func (d *JPPhone) Scan(data []byte) []Finding {
	normalized, posMap := normalizeDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized performs phone number detection on normalized data.
// orig is the original (possibly full-width) input used for matched text.
func (d *JPPhone) scanNormalized(orig, data []byte, posMap []int) []Finding {
	var findings []Finding
	var logContext numericLogContext

	i := 0
	for i < len(data) {
		// Escape bytes cannot become part of a numeric candidate.
		if data[i] == '%' && normalizedEscapeSeparator(orig, posMap, len(data), i) {
			i += 3
			continue
		}
		if data[i] == '+' {
			if f, end, ok := d.international(orig, data, posMap, i, &logContext); ok {
				findings = append(findings, f)
				i = end
				continue
			}
		}
		if data[i] != '0' {
			i++
			continue
		}

		// Check that '0' is not part of a longer word-like token.
		// Underscores are treated as word characters to prevent matching
		// identifiers like _09012345678.
		if !normalizedIdentifierStart(orig, data, posMap, i) {
			i++
			continue
		}

		start := i
		digits, end := appendSeparatedDigits(data, start, make([]byte, 0, phoneDigitCapacity), phoneSeparator)
		if !jpPhoneWhole(data, digits, end) {
			i = end
			continue
		}

		phoneType := classifyJPPhone(digits, len(digits))
		if phoneType == "" || logContext.fragment(data, start, end) {
			i = end
			continue
		}

		findings = append(findings, labeledViewFinding(d.Name(), orig, posMap, start, end, jpPhoneConfidence(phoneType)))
		i = end
	}

	return findings
}

// international recognizes the +81 form, such as +81-90-1234-5678,
// +819012345678 and +81 (0)3-1234-5678. The national number after the
// country code drops its leading zero, which classification restores, and
// the span starts at the plus sign.
func (d *JPPhone) international(orig, data []byte, posMap []int, start int, logContext *numericLogContext) (Finding, int, bool) {
	if start+3 >= len(data) || data[start+1] != '8' || data[start+2] != '1' || (start > 0 && isIdentifierByte(data[start-1])) {
		return Finding{}, start + 1, false
	}
	digits, end := appendSeparatedDigits(data, start+3, make([]byte, 1, phoneDigitCapacity), phoneSeparator)
	digits[0] = '0'
	if len(digits) > 1 && digits[1] == '0' {
		digits = digits[1:] // The (0) trunk prefix is already the leading zero.
	}
	if end <= start+3 || !jpPhoneWhole(data, digits, end) {
		return Finding{}, start + 1, false
	}
	phoneType := classifyJPPhone(digits, len(digits))
	if phoneType == "" || logContext.fragment(data, start, end) {
		return Finding{}, end, false
	}
	return labeledViewFinding(d.Name(), orig, posMap, start, end, jpPhoneConfidence(phoneType)), end, true
}

// jpPhoneWhole reports whether a candidate does not continue with word
// characters and has the 10 or 11 digits of a Japanese number.
func jpPhoneWhole(data, digits []byte, end int) bool {
	// Check that the sequence doesn't continue with word characters.
	if end < len(data) && isIdentifierByte(data[end]) {
		return false
	}
	digitLen := len(digits)
	return digitLen >= 10 && digitLen <= 11
}

// jpPhoneConfidence gives mobile and well-known prefixes a higher score than
// landlines.
func jpPhoneConfidence(phoneType JPPhoneType) float64 {
	confidence := 0.8
	// Higher confidence for mobile and well-known prefixes.
	if phoneType != JPPhoneTypeLandline {
		confidence = 0.9
	}
	return confidence
}

// classifyJPPhone returns the phone type based on the prefix and digit count,
// or "" if the number does not match any known Japanese phone format.
func classifyJPPhone(digits []byte, digitLen int) JPPhoneType {
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(digits) < 2 {
		return ""
	}

	// Check prefix rules for mobile, IP phone, and toll-free numbers.
	for _, rule := range jpPhoneRules() {
		if digitLen == rule.digitLen && len(digits) >= 1+len(rule.prefix) {
			if string(digits[1:1+len(rule.prefix)]) == rule.prefix {
				return rule.result
			}
		}
	}

	// Landline: 0[1-9]X (10 digits) with valid area code prefix.
	if digitLen == 10 && digits[1] >= '1' && digits[1] <= '9' && isValidLandlinePrefix(digits) {
		return JPPhoneTypeLandline
	}

	return ""
}

// isValidLandlinePrefix checks whether the first 3 digits form a plausible
// Japanese landline area code prefix. This is a best-effort blocklist that
// rejects known non-landline prefixes, NOT an exhaustive area code database.
// Some non-existent area codes may still pass this check, resulting in
// false positives. For use cases that require strict area code validation,
// consider post-filtering with an authoritative area code list.
//
// Rejected prefixes:
//   - 050, 070, 080, 090: require 11 digits (mobile/IP phone), not 10
//   - 020, 021, 051, 057, 060, 071, 081, 091: excluded from the landline branch
func isValidLandlinePrefix(digits []byte) bool {
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(digits) < 3 {
		return false
	}
	switch string(digits[1:3]) {
	case "50", "70", "80", "90", "20", "21", "51", "57", "60", "71", "81", "91":
		return false
	default:
		return true
	}
}

// phoneDigits retains separator grammar and stops the span at the final digit.
// phoneDigitCapacity sizes the digit buffer of a phone or MyNumber candidate,
// so a run of typical length stays on the stack.
const phoneDigitCapacity = 32
