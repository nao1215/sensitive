package detector

// ABARoutingDetail holds US ABA routing number-specific detail information.
type ABARoutingDetail struct {
	// FederalReserveDistrict is a human-readable label for the Federal Reserve
	// routing symbol range (e.g., "01-Boston", "02-New York").
	FederalReserveDistrict string
}

// ABARouting detects US ABA routing transit numbers in text.
//
// ABA routing numbers are 9-digit identifiers assigned by the American Bankers
// Association to financial institutions. They are used in ACH transfers, wire
// transfers, and check processing.
//
// Detection logic:
//  1. Scan for sequences of exactly 9 consecutive ASCII digits
//  2. Validate the first two digits are a recognized Federal Reserve routing
//     symbol (01-12 for normal, 21-32 for thrift, 61-72 for electronic, 80 for traveler's cheques)
//  3. Validate the checksum: 3*(d1+d4+d7) + 7*(d2+d5+d8) + (d3+d6+d9) ≡ 0 (mod 10)
//
// Confidence:
//   - 0.85: routing symbol prefix and checksum are both valid
//
// Numbers that fail the checksum are unconditionally rejected regardless
// of prefix range or context keywords. In financial systems checksum
// validation is mandatory and relaxing it introduces unacceptable false
// positive risk.
type ABARouting struct{}

// NewABARouting creates a new US ABA routing number detector.
func NewABARouting() *ABARouting {
	return &ABARouting{}
}

// Name returns "aba_routing".
func (d *ABARouting) Name() DetectorName {
	return NameABARouting
}

// Hints returns nil, causing the Scanner to always run ABA detection.
// ABA routing numbers are 9-digit sequences that can start with any of
// the digits 0-8. Short single-digit hints would match nearly all input
// and provide no filtering benefit. The Scan method itself performs fast
// rejection (digit count + prefix range + checksum) so the cost of always
// scanning is negligible.
func (d *ABARouting) Hints() [][]byte {
	return nil
}

// Scan examines data for ABA routing numbers and returns findings.
func (d *ABARouting) Scan(data []byte) []Finding {
	normalized, posMap := NormalizeFullWidthDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized scans the normalized (ASCII) byte slice for ABA routing numbers.
func (d *ABARouting) scanNormalized(orig, data []byte, posMap []int) []Finding {
	var findings []Finding

	for i := 0; i < len(data); i++ {
		if !isDigit(data[i]) {
			continue
		}

		// Word boundary: preceding character must not be alphanumeric.
		if i > 0 && isAlphaNum(data[i-1]) {
			continue
		}

		// Need exactly 9 consecutive digits.
		end := i
		for end < len(data) && isDigit(data[end]) {
			end++
		}
		if end-i != 9 {
			i = end - 1
			continue
		}

		digits := data[i:end]

		// Validate Federal Reserve routing symbol (first two digits).
		district := abaFederalReserveDistrict(digits)
		if district == "" {
			i = end - 1
			continue
		}

		// Word boundary: following character must not be alphanumeric.
		if end < len(data) && isAlphaNum(data[end]) {
			i = end - 1
			continue
		}

		// Validate ABA checksum. Numbers that fail the checksum are
		// unconditionally rejected to prevent false positives in
		// financial contexts.
		if !validateABAChecksum(digits) {
			i = end - 1
			continue
		}
		confidence := 0.85

		origStart := posMap[i]
		origEnd := posMap[end-1] + 1
		// Adjust origEnd for multi-byte characters.
		if end-1 < len(posMap) {
			for origEnd < len(orig) && origEnd > origStart {
				// Find the true end by checking the next position map entry.
				if end < len(posMap) {
					origEnd = posMap[end]
					break
				}
				origEnd = len(orig)
				break
			}
		}

		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        origStart,
			End:          origEnd,
			Confidence:   confidence,
			RawValue:     string(orig[origStart:origEnd]),
			Detail:       &ABARoutingDetail{FederalReserveDistrict: district},
		})

		i = end - 1
	}

	return findings
}

// validateABAChecksum validates the ABA routing number checksum.
// The formula is: 3*(d1+d4+d7) + 7*(d2+d5+d8) + (d3+d6+d9) ≡ 0 (mod 10)
// where d1..d9 are the 9 digits of the routing number.
func validateABAChecksum(digits []byte) bool {
	if len(digits) != 9 {
		return false
	}

	sum := 3*(int(digits[0]-'0')+int(digits[3]-'0')+int(digits[6]-'0')) +
		7*(int(digits[1]-'0')+int(digits[4]-'0')+int(digits[7]-'0')) +
		(int(digits[2]-'0') + int(digits[5]-'0') + int(digits[8]-'0'))

	return sum%10 == 0
}

// abaFederalReserveDistrict returns the Federal Reserve district label for the
// given routing number, or an empty string if the prefix is not valid.
// Valid ranges: 01-12 (normal), 21-32 (thrift), 61-72 (electronic), 80 (traveler's cheques).
func abaFederalReserveDistrict(digits []byte) string {
	if len(digits) < 2 {
		return ""
	}
	prefix := int(digits[0]-'0')*10 + int(digits[1]-'0')

	switch {
	case prefix >= 1 && prefix <= 12:
		return abaDistrictNames[prefix]
	case prefix >= 21 && prefix <= 32:
		return abaDistrictNames[prefix-20]
	case prefix >= 61 && prefix <= 72:
		return abaDistrictNames[prefix-60]
	case prefix == 80:
		return "Traveler's Cheques"
	default:
		return ""
	}
}

// abaDistrictNames maps Federal Reserve district numbers (1-12) to their names.
var abaDistrictNames = map[int]string{
	1:  "01-Boston",
	2:  "02-New York",
	3:  "03-Philadelphia",
	4:  "04-Cleveland",
	5:  "05-Richmond",
	6:  "06-Atlanta",
	7:  "07-Chicago",
	8:  "08-St. Louis",
	9:  "09-Minneapolis",
	10: "10-Kansas City",
	11: "11-Dallas",
	12: "12-San Francisco",
}
