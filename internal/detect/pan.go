package detect

import (
	"unicode/utf8"

	"github.com/nao1215/embargo/internal/ascii"
)

// CardBrand identifies a payment card brand; see the Brand* constants.
type CardBrand string

// Card brand constants identify the issuer for prefix and length validation.
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

// Card numbers have 13 to 19 digits.
const (
	panMinDigits = 13
	panMaxDigits = 19
)

// PAN implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindPAN.
type PAN struct{}

// NewPAN checks issuer prefixes, lengths and Luhn confidence.
func NewPAN() *PAN {
	return &PAN{}
}

// Name returns "pan".
func (d *PAN) Name() DetectorName {
	return NamePAN
}

// Hints returns the pre-filter substrings for [PAN].
func (d *PAN) Hints() [][]byte {
	return [][]byte{
		[]byte("4"), // Visa (half-width)
		[]byte("5"), // Mastercard 51-55 (half-width)
		[]byte("3"), // Amex (34,37), JCB (3528-3589), Diners (half-width)
		//nolint:gocritic // The trailing comment names the card prefixes represented by this hint.
		[]byte("6"), // Discover (6011, 644-649, 65) (half-width)
		//nolint:gocritic // The trailing comment names the card prefixes represented by this hint.
		[]byte("2"),        // Mastercard (2221-2720) (half-width)
		{0xEF, 0xBC, 0x94}, // ４ Visa (full-width, U+FF14)
		{0xEF, 0xBC, 0x95}, // ５ Mastercard 51-55 (full-width, U+FF15)
		{0xEF, 0xBC, 0x93}, // ３ Amex/JCB/Diners (full-width, U+FF13)
		{0xEF, 0xBC, 0x96}, // ６ Discover (full-width, U+FF16)
		{0xEF, 0xBC, 0x92}, // ２ Mastercard 2-series (full-width, U+FF12)
	}
}

// Scan returns matches in data using the rules documented on [PAN].
func (d *PAN) Scan(data []byte) []Finding { return d.appendScan(nil, data) }

func (d *PAN) appendScan(dst []Finding, data []byte) []Finding {
	// One pass decides both the ASCII fast path and the digit count that
	// normalizeDigits and appendNormalized would otherwise each walk for.
	digits := 0
	for _, b := range data {
		if b >= utf8.RuneSelf {
			normalized, posMap := NormalizeFullWidthDigits(data)
			return d.appendNormalized(dst, data, normalized, posMap)
		}
		if ascii.IsDigit(b) {
			digits++
		}
	}
	if digits < panMinDigits {
		return dst
	}
	return d.appendNormalized(dst, data, data, nil)
}

// appendNormalized appends the PAN findings of normalized (half-width) data
// to dst. orig is the original (possibly full-width) input; posMap maps
// normalized byte positions back to original byte positions. Context
// confidence uses orig.
func (d *PAN) appendNormalized(dst []Finding, orig, data []byte, posMap []int) []Finding {
	// Every candidate needs at least panMinDigits digits of data, so text with
	// fewer, such as a key with a short index, cannot produce a finding.
	if !hasDigits(data, panMinDigits) {
		return dst
	}
	return scanNumeric(dst, orig, data, posMap, d.candidate, true)
}

// candidate checks the card number that may start at i and returns where
// scanning continues.
func (d *PAN) candidate(orig, data []byte, posMap []int, i int) (Finding, int, bool) {
	if !ascii.IsDigit(data[i]) {
		return Finding{}, i + 1, false
	}
	// Card digits fit the array; a longer run grows past it and is rejected by length.
	var stack [panMaxDigits + 1]byte
	digits, end := cardDigits(data, i, stack[:0])
	bounded := panBounded(orig, data, posMap, i, end)
	f, ok := d.evaluateCandidate(orig, posMap, digits, len(digits), i, end)
	return f, end, ok && bounded
}

// cardDigits extracts the digits of a candidate separated by spaces or
// hyphens, or written in dotted groups.
func cardDigits(data []byte, start int, digits []byte) (run []byte, end int) {
	if dotted, dottedEnd, ok := dottedCardDigits(data, start, digits); ok {
		return dotted, dottedEnd
	}
	return appendSeparatedDigits(data, start, digits, cardSeparator)
}

// dottedCardDigits accepts a card written as four dot-separated groups of
// four digits, 4111.1111.1111.1111. Other dotted runs are versions, OIDs or
// addresses, so the grouping must be exact and no further dotted digits follow.
func dottedCardDigits(data []byte, start int, digits []byte) (run []byte, end int, ok bool) {
	const width, group = len("4111.1111.1111.1111"), len("4111.")
	end = start + width
	if end > len(data) {
		return nil, start, false
	}
	for i, c := range data[start:end] {
		if i%group == group-1 {
			if c != '.' {
				return nil, start, false
			}
			continue
		}
		if !ascii.IsDigit(c) {
			return nil, start, false
		}
		digits = append(digits, c)
	}
	if end < len(data) && (ascii.IsDigit(data[end]) || (data[end] == '.' && end+1 < len(data) && ascii.IsDigit(data[end+1]))) {
		return nil, start, false
	}
	return digits, end, true
}

// panBounded reports whether [start, end) is not embedded in an identifier,
// allowing an encoded separator before the original start.
func panBounded(orig, data []byte, posMap []int, start, end int) bool {
	leading := leadingBoundaryView(orig, posMap, data, start, isIdentifierByte)
	trailing := trailingBoundary(data, end, isIdentifierByte)
	return leading && trailing
}

// evaluateCandidate checks whether a digit sequence is a valid PAN and returns
// a Finding if it meets the confidence threshold. It returns (Finding, false)
// when the candidate should be skipped.
func (d *PAN) evaluateCandidate(orig []byte, posMap []int, digits []byte, digitLen, start, end int) (Finding, bool) {
	if digitLen < panMinDigits || digitLen > panMaxDigits {
		return Finding{}, false
	}

	confidence := 0.3 // digit count in valid range

	brand := identifyBrand(digits)
	if brand == "" {
		return Finding{}, false
	}
	confidence += 0.3 // known BIN prefix

	// Every issued card satisfies Luhn and its brand's lengths, so digits
	// that fail either are an order, request or trace ID that starts like a
	// card, not a card.
	if !passesLuhn(digits) || !isExpectedLength(brand, digitLen) {
		return Finding{}, false
	}
	// Japanese JAN product codes are 13-digit EAN codes starting with 45 or
	// 49, which collide with the obsolete 13-digit Visa length. A 13-digit
	// candidate whose EAN check digit also holds is a product code.
	if digitLen == eanDigits && passesEAN13(digits) {
		return Finding{}, false
	}
	confidence += 0.4 // Luhn + expected length

	return labeledViewFinding(d.Name(), orig, posMap, start, end, confidence, cardLabels()...), true
}

// passesEAN13 validates the EAN-13 (GTIN-13) check digit: weights 1 and 3
// alternate from the left over the first twelve digits.
func passesEAN13(digits []byte) bool {
	const base, oddWeight = 10, 3
	sum := 0
	for i, digit := range digits[:eanDigits-1] {
		n := int(digit - '0')
		if i%2 == 1 {
			n *= oddWeight
		}
		sum += n
	}
	return (base-sum%base)%base == int(digits[eanDigits-1]-'0')
}

// eanDigits is the length of an EAN-13 (JAN) code.
const eanDigits = 13

// cardLabels returns the words that name a payment card, as in card_id or
// credit card number, and keep its confidence under a record label.
func cardLabels() []string { return []string{"card", "pan", "cc", "credit", "カード"} }

// passesLuhn implements the Luhn algorithm (MOD 10) for check digit validation.
// It processes digits from right to left, doubling every second digit.
// A valid number produces a sum divisible by 10.
func passesLuhn[T string | []byte](digits T) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if len(digits) >= 4 {
			//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return length == 16
	case BrandAmex:
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return length == 15
	case BrandJCB:
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return length == 16
	case BrandDiscover:
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		return length == 16
	case BrandDiners:
		return length >= 14 && length <= 16
	case BrandUnionPay:
		return length >= 16 && length <= 19
	}
	return false
}
