package detector

// JPPhoneType is the type-safe identifier for a Japanese phone number type.
// Use the JPPhoneType* constants for comparison with [JPPhoneDetail.PhoneType].
//
//	if detail.PhoneType == detector.JPPhoneTypeMobile { ... }
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

// JPPhoneDetail holds Japanese phone number-specific detail information.
type JPPhoneDetail struct {
	// PhoneType is the classification of the phone number.
	// Compare with the JPPhoneType* constants (e.g., [JPPhoneTypeMobile],
	// [JPPhoneTypeLandline]).
	PhoneType JPPhoneType
}

// jpPhoneRule defines a prefix-based classification rule for Japanese phone numbers.
// Each rule matches a specific digit length and a prefix (starting at digits[1])
// to produce a JPPhoneType.
type jpPhoneRule struct {
	digitLen int
	prefix   string // matches digits[1:1+len(prefix)]
	result   JPPhoneType
}

// jpPhoneRules is the table of prefix-based classification rules for Japanese
// phone numbers. Rules are evaluated in order; the first match wins.
var jpPhoneRules = []jpPhoneRule{
	{11, "90", JPPhoneTypeMobile},
	{11, "80", JPPhoneTypeMobile},
	{11, "70", JPPhoneTypeMobile},
	{11, "50", JPPhoneTypeIPPhone},
	{11, "20", JPPhoneTypeM2M},
	{11, "60", JPPhoneTypeService},
	{10, "120", JPPhoneTypeTollFree},
	{11, "800", JPPhoneTypeTollFree},
}

// invalidLandlinePrefixes contains digit pairs (digits[1:3]) that are NOT valid
// Japanese landline area code prefixes.
//
// Rejected prefixes:
//   - 050, 070, 080, 090: require 11 digits (mobile/IP phone), not 10
//   - 020, 021, 051, 057, 060, 071, 081, 091: not assigned as area codes
var invalidLandlinePrefixes = map[string]bool{
	"50": true, "70": true, "80": true, "90": true,
	"20": true, "21": true, "51": true, "57": true,
	"60": true, "71": true, "81": true, "91": true,
}

// JPPhone detects Japanese phone numbers in text.
//
// Supported formats:
//   - Landline: 03-1234-5678, 03(1234)5678, 0312345678
//   - Mobile: 090-1234-5678, 090 1234 5678, 09012345678
//   - IP phone: 050-1234-5678
//   - Toll-free: 0120-123-456, 0800-123-4567
//   - M2M/IoT: 020-1234-5678
//   - Service: 060-1234-5678
//
// Detection logic:
//  1. Scan for sequences starting with '0' (allowing '-', '(', ')', ' ' separators)
//  2. Count digits (must be 10-11)
//  3. Validate prefix against known area codes and mobile prefixes
//
// To avoid false positives with postal codes (7-digit XXX-XXXX format) and
// other numeric sequences, the detector requires the '0' prefix and validates
// the total digit count strictly. Underscores are treated as word characters,
// so identifiers like _09012345678 are not detected.
//
// Full-width digits (e.g., ０９０−１２３４−５６７８) are also supported
// through normalization.
type JPPhone struct{}

// NewJPPhone creates a new Japanese phone number detector.
func NewJPPhone() *JPPhone {
	return &JPPhone{}
}

// Name returns "phone_jp".
func (d *JPPhone) Name() DetectorName {
	return NameJPPhone
}

// Hints returns byte sequences that may indicate the presence of a Japanese
// phone number. All Japanese phone numbers start with '0'.
//
// NOTE: The single-byte hint "0" is broad and will match most inputs
// containing any digit zero. However, it still provides value by skipping
// inputs that contain no '0' at all (e.g., pure alphabetic text). For
// stricter pre-filtering, multi-byte prefixes like "03", "06", "090" could
// be used, but this would require an exhaustive list of all valid area codes.
//
// The full-width equivalent ０ (U+FF10) is included because Scan normalizes
// full-width digits before detection. Without this hint the Scanner's
// pre-filter would reject full-width-only phone numbers before Scan runs.
func (d *JPPhone) Hints() [][]byte {
	return [][]byte{
		[]byte("0"),
		{0xEF, 0xBC, 0x90}, // ０ full-width zero (U+FF10)
	}
}

// Scan examines data for Japanese phone numbers and returns findings.
// It normalizes full-width digits before scanning.
func (d *JPPhone) Scan(data []byte) []Finding {
	normalized, posMap := NormalizeFullWidthDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized performs phone number detection on normalized data.
// orig is the original (possibly full-width) input used for RawValue.
func (d *JPPhone) scanNormalized(orig []byte, data []byte, posMap []int) []Finding {
	var findings []Finding

	i := 0
	for i < len(data) {
		if data[i] != '0' {
			i++
			continue
		}

		// Check that '0' is not part of a longer word-like token.
		// Underscores are treated as word characters to prevent matching
		// identifiers like _09012345678.
		if i > 0 && isPhoneWordChar(data[i-1]) {
			i++
			continue
		}

		// Extract digit sequence with separators.
		start := i
		var digits []byte
		j := i
		for j < len(data) && isPhoneSepChar(data[j]) {
			if isDigit(data[j]) {
				digits = append(digits, data[j])
			}
			j++
		}
		end := j

		// Trim trailing non-digit separators (e.g., trailing spaces) so that
		// the boundary check and RawValue do not include them.
		for end > start && !isDigit(data[end-1]) {
			end--
		}

		// Check that the sequence doesn't continue with word characters.
		if end < len(data) && isPhoneWordChar(data[end]) {
			i = end
			continue
		}

		digitLen := len(digits)
		if digitLen < 10 || digitLen > 11 {
			i = end
			continue
		}

		phoneType := classifyJPPhone(digits, digitLen)
		if phoneType == "" {
			i = end
			continue
		}

		confidence := 0.8
		// Higher confidence for mobile and well-known prefixes.
		if phoneType != JPPhoneTypeLandline {
			confidence = 0.9
		}

		origStart, origEnd := mapOriginalRange(posMap, start, end)

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        origStart,
			End:          origEnd,
			Confidence:   confidence,
			RawValue:     string(orig[origStart:origEnd]),
			Detail:       &JPPhoneDetail{PhoneType: phoneType},
		})
		i = end
	}

	return findings
}

// isPhoneSepChar reports whether b is a digit or phone number separator.
// Space is included to support formats like "090 1234 5678".
func isPhoneSepChar(b byte) bool {
	return isDigit(b) || b == '-' || b == '(' || b == ')' || b == ' '
}

// isPhoneWordChar reports whether b is a character that forms part of a
// word-like token. Phone numbers adjacent to these characters are rejected
// to avoid matching identifiers (e.g., _09012345678 or var09012345678).
func isPhoneWordChar(b byte) bool {
	return isAlphaNum(b) || b == '_'
}

// classifyJPPhone returns the phone type based on the prefix and digit count,
// or "" if the number does not match any known Japanese phone format.
func classifyJPPhone(digits []byte, digitLen int) JPPhoneType {
	if len(digits) < 2 {
		return ""
	}

	// Check prefix rules for mobile, IP phone, and toll-free numbers.
	for _, rule := range jpPhoneRules {
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
//   - 020, 021, 051, 057, 071, 081, 091: not assigned as area codes
func isValidLandlinePrefix(digits []byte) bool {
	if len(digits) < 3 {
		return false
	}
	return !invalidLandlinePrefixes[string(digits[1:3])]
}
