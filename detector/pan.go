package detector

// CardBrand is the type-safe identifier for a payment card brand.
// Use the Brand* constants for comparison with [PANDetail.Brand].
//
//	if detail.Brand == detector.BrandVisa { ... }
type CardBrand string

// Card brand constants. Use these with [PANDetail.Brand] to identify
// the issuing network of a detected card number.
const (
	// BrandVisa identifies Visa cards (prefix 4).
	BrandVisa CardBrand = "Visa"
	// BrandMastercard identifies Mastercard cards (prefix 51-55 or 2221-2720).
	BrandMastercard CardBrand = "Mastercard"
	// BrandAmex identifies American Express cards (prefix 34 or 37).
	BrandAmex CardBrand = "Amex"
	// BrandJCB identifies JCB cards (prefix 3528-3589).
	BrandJCB CardBrand = "JCB"
	// BrandDiscover identifies Discover cards (prefix 6011, 644-649, 65).
	BrandDiscover CardBrand = "Discover"
	// BrandDiners identifies Diners Club cards (prefix 300-305, 36, 38).
	BrandDiners CardBrand = "Diners"
	// BrandUnionPay identifies UnionPay cards (prefix 62).
	BrandUnionPay CardBrand = "UnionPay"
)

// PANDetail holds credit card-specific detail information for a PAN finding.
type PANDetail struct {
	// Brand is the card brand identified by the BIN prefix.
	// Compare with the Brand* constants (e.g., [BrandVisa], [BrandMastercard]).
	Brand CardBrand
	// BIN is the first 6 digits of the card number (Bank Identification Number).
	BIN string
	// Last4 is the last 4 digits of the card number.
	Last4 string
	// Luhn indicates whether the number passes the Luhn check digit algorithm.
	Luhn bool
	// Length is the total number of digits in the card number.
	Length int
}

// PAN detects credit card numbers (Primary Account Numbers) in text.
//
// Detection uses a dedicated parser rather than regular expressions:
//  1. Scan for digit sequences (allowing '-' and ' ' as separators)
//  2. Check that the digit count is 13-19 (valid PAN range)
//  3. Validate against known BIN/IIN prefix table (Visa, Mastercard, Amex, etc.)
//  4. Run the Luhn check digit algorithm
//  5. Verify that the digit count matches the expected length for the card brand
//
// Confidence is calculated cumulatively:
//   - 13-19 digits: 0.3
//   - + Known BIN prefix match: +0.3 (= 0.6)
//   - + Luhn check passes AND expected length for brand: +0.4 (= 1.0)
//   - Luhn passes but length does NOT match brand: confidence drops to 0.4
//     (below detection threshold, effectively rejected)
//
// The expected-length check is mandatory when Luhn passes. In financial
// contexts, a digit sequence that passes Luhn but has the wrong length
// for its brand prefix (e.g., 19-digit Visa) is almost certainly not a
// genuine card number.
type PAN struct{}

// NewPAN creates a new PAN detector.
func NewPAN() *PAN {
	return &PAN{}
}

// Name returns "pan".
func (d *PAN) Name() DetectorName {
	return NamePAN
}

// Hints returns byte sequences that may indicate the presence of a PAN.
// Since PANs are composed of digits, the hints target the first digit of
// each known card brand prefix. This provides limited filtering precision,
// so the Scan method applies BIN + Luhn validation to eliminate false positives.
//
// Full-width digit equivalents (U+FF10–U+FF19) are included because Scan
// normalizes full-width digits before detection. Without these hints the
// Scanner's pre-filter would reject full-width-only PANs before Scan runs.
func (d *PAN) Hints() [][]byte {
	return [][]byte{
		[]byte("4"),        // Visa (half-width)
		[]byte("5"),        // Mastercard 51-55 (half-width)
		[]byte("3"),        // Amex (34,37), JCB (3528-3589), Diners (half-width)
		[]byte("6"),        // Discover (6011, 644-649, 65) (half-width)
		[]byte("2"),        // Mastercard (2221-2720) (half-width)
		{0xEF, 0xBC, 0x94}, // ４ Visa (full-width, U+FF14)
		{0xEF, 0xBC, 0x95}, // ５ Mastercard 51-55 (full-width, U+FF15)
		{0xEF, 0xBC, 0x93}, // ３ Amex/JCB/Diners (full-width, U+FF13)
		{0xEF, 0xBC, 0x96}, // ６ Discover (full-width, U+FF16)
		{0xEF, 0xBC, 0x92}, // ２ Mastercard 2-series (full-width, U+FF12)
	}
}

// Scan examines data for credit card numbers and returns findings.
//
// The algorithm scans for contiguous digit sequences (with optional '-' or ' '
// separators), then applies BIN prefix matching and Luhn validation.
// Full-width digits are normalized before scanning.
func (d *PAN) Scan(data []byte) []Finding {
	normalized, posMap := NormalizeFullWidthDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized performs PAN detection on normalized (half-width) data.
// orig is the original (possibly full-width) input; posMap maps normalized
// byte positions back to original byte positions. RawValue is taken from
// orig so it matches the original text exactly.
func (d *PAN) scanNormalized(orig []byte, data []byte, posMap []int) []Finding {
	var findings []Finding

	i := 0
	for i < len(data) {
		// Skip non-digit characters.
		if !isDigit(data[i]) {
			i++
			continue
		}

		// Found a digit — try to extract a candidate PAN.
		start := i
		var digits []byte
		j := i
		for j < len(data) && (isDigit(data[j]) || data[j] == '-' || data[j] == ' ') {
			if isDigit(data[j]) {
				digits = append(digits, data[j])
			}
			j++
		}
		// Trim trailing separators (spaces, hyphens) so the end position
		// points to the character after the last digit.
		end := j
		for end > start && !isDigit(data[end-1]) {
			end--
		}

		// Check digit count: valid PANs are 13-19 digits.
		digitLen := len(digits)
		if f, ok := d.evaluateCandidate(orig, posMap, digits, digitLen, start, end); ok {
			findings = append(findings, f)
		}

		// Move past the current candidate to continue scanning.
		i = end
	}

	return findings
}

// evaluateCandidate checks whether a digit sequence is a valid PAN and returns
// a Finding if it meets the confidence threshold. It returns (Finding, false)
// when the candidate should be skipped.
func (d *PAN) evaluateCandidate(orig []byte, posMap []int, digits []byte, digitLen, start, end int) (Finding, bool) {
	if digitLen < 13 || digitLen > 19 {
		return Finding{}, false
	}

	confidence := 0.3 // digit count in valid range

	brand := identifyBrand(digits)
	if brand == "" {
		return Finding{}, false
	}
	confidence += 0.3 // known BIN prefix

	luhnOK := passesLuhn(digits)
	if luhnOK {
		if isExpectedLength(brand, digitLen) {
			confidence += 0.4 // Luhn + expected length
		} else {
			// Luhn passes but length does not match the brand.
			// In financial contexts this is almost certainly not
			// a genuine card of this brand. Drop confidence below
			// the detection threshold.
			confidence = 0.4
		}
	}

	// Only report findings with BIN match (confidence >= 0.6).
	if confidence < 0.6 {
		return Finding{}, false
	}

	binStr := string(digits[:min(6, len(digits))])
	last4 := string(digits[max(0, len(digits)-4):])

	origStart, origEnd := mapOriginalRange(posMap, start, end)

	return Finding{
		DetectorName: d.Name(),
		Start:        origStart,
		End:          origEnd,
		Confidence:   confidence,
		RawValue:     string(orig[origStart:origEnd]),
		Detail: &PANDetail{
			Brand:  brand,
			BIN:    binStr,
			Last4:  last4,
			Luhn:   luhnOK,
			Length: digitLen,
		},
	}, true
}

// passesLuhn implements the Luhn algorithm (MOD 10) for check digit validation.
// It processes digits from right to left, doubling every second digit.
// A valid number produces a sum divisible by 10.
func passesLuhn(digits []byte) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// identifyBrand returns the card brand based on the BIN prefix, or ""
// if the prefix does not match any known brand.
//
// Supported brands and their prefix rules:
//   - Visa: starts with 4
//   - Mastercard: 51-55 or 2221-2720
//   - Amex: 34 or 37
//   - JCB: 3528-3589
//   - Discover: 6011, 644-649, 65
//   - Diners Club: 300-305, 36, 38
//   - UnionPay: 62
func identifyBrand(digits []byte) CardBrand {
	if len(digits) < 4 {
		return ""
	}
	switch digits[0] {
	case '4':
		return BrandVisa
	case '5':
		if digits[1] >= '1' && digits[1] <= '5' {
			return BrandMastercard
		}
		return ""
	case '3':
		return matchPrefix3(digits)
	case '6':
		return matchPrefix6(digits)
	case '2':
		// Mastercard 2-series: prefix range 2221–2720.
		// Use full 4-digit comparison for clarity and precision.
		if len(digits) >= 4 {
			v := int(digits[0]-'0')*1000 + int(digits[1]-'0')*100 + int(digits[2]-'0')*10 + int(digits[3]-'0')
			if v >= 2221 && v <= 2720 {
				return BrandMastercard
			}
		}
		return ""
	}
	return ""
}

// matchPrefix3 identifies card brands whose numbers start with '3'.
//
// Prefix rules handled:
//   - Amex: 34 or 37
//   - Diners Club: 36, 38, or 300-305
//   - JCB: 3528-3589 (digits[1]=='5', then two-digit sub-range 28-89)
func matchPrefix3(digits []byte) CardBrand {
	switch digits[1] {
	case '4', '7':
		return BrandAmex
	case '6', '8':
		return BrandDiners
	case '5':
		// JCB: 3528-3589
		if len(digits) >= 4 {
			v := (digits[2]-'0')*10 + (digits[3] - '0')
			if v >= 28 && v <= 89 {
				return BrandJCB
			}
		}
	case '0':
		// Diners: 300-305
		if len(digits) >= 3 && digits[2] >= '0' && digits[2] <= '5' {
			return BrandDiners
		}
	}
	return ""
}

// matchPrefix6 identifies card brands whose numbers start with '6'.
//
// Prefix rules handled:
//   - Discover: 6011, 644-649, or 65
//   - UnionPay: 62
func matchPrefix6(digits []byte) CardBrand {
	switch digits[1] {
	case '0':
		// Discover: 6011
		if len(digits) >= 4 && digits[2] == '1' && digits[3] == '1' {
			return BrandDiscover
		}
	case '4':
		// Discover: 644-649
		if len(digits) >= 3 && digits[2] >= '4' && digits[2] <= '9' {
			return BrandDiscover
		}
	case '5':
		return BrandDiscover
	case '2':
		return BrandUnionPay
	}
	return ""
}

// isExpectedLength checks whether the digit count matches the expected
// length for the given card brand.
func isExpectedLength(brand CardBrand, length int) bool {
	switch brand {
	case BrandVisa:
		return length == 16 || length == 13
	case BrandMastercard:
		return length == 16
	case BrandAmex:
		return length == 15
	case BrandJCB:
		return length == 16
	case BrandDiscover:
		return length == 16
	case BrandDiners:
		return length >= 14 && length <= 16
	case BrandUnionPay:
		return length >= 16 && length <= 19
	}
	return false
}

// isDigit reports whether b is an ASCII digit ('0'-'9').
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
