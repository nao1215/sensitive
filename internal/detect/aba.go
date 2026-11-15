package detect

// ABARoutingDetail holds US ABA routing number-specific detail information.
type ABARoutingDetail struct {
	// FederalReserveDistrict is a human-readable label for the Federal Reserve
	// routing symbol range (e.g., "01-Boston", "02-New York").
	FederalReserveDistrict string
}

// ABARouting detects US routing transit numbers used for ACH, wire transfers, and checks.
//
//  1. Extract exactly nine digits and require a routing prefix in 01–12, 21–32, 61–72, or 80 (normal, thrift, electronic, or traveler's checks).
//  2. Require 3*(d1+d4+d7) + 7*(d2+d5+d8) + (d3+d6+d9) to be divisible by 10; reject every checksum failure.
//  3. Score a valid match as 0.85.
type ABARouting struct{}

// NewABARouting creates a new US ABA routing number detect.
func NewABARouting() *ABARouting {
	return &ABARouting{}
}

// Name returns "aba_routing".
func (d *ABARouting) Name() DetectorName {
	return NameABARouting
}

// Hints returns nil because no selective exhaustive substring is available.
func (d *ABARouting) Hints() [][]byte {
	return nil
}

// Scan returns matches in data using the rules documented on [ABARouting].
func (d *ABARouting) Scan(data []byte) []Finding {
	normalized, posMap := NormalizeFullWidthDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized scans the normalized (ASCII) byte slice for ABA routing numbers.
func (d *ABARouting) scanNormalized(orig, data []byte, posMap []int) []Finding {
	var findings []Finding

	for i := 0; i < len(data); i++ {
		// Escape bytes cannot become part of a numeric candidate.
		if data[i] == '%' && i+3 <= len(data) && encodedSeparatorBefore(orig, posMap[i+3]) {
			i += 2
			continue
		}
		if !isDigit(data[i]) {
			continue
		}

		// Word boundary: preceding character must not be alphanumeric.
		if i > 0 && isAlphaNum(data[i-1]) && !encodedSeparatorBefore(orig, posMap[i]) {
			continue
		}

		// Need exactly 9 consecutive digits.
		end := i
		for end < len(data) && isDigit(data[end]) {
			end++
		}
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		if end-i != 9 {
			i = end - 1
			continue
		}

		// A decimal component (including an RFC3339 fractional second) is not
		// a standalone routing number, even when its digits satisfy the checksum.
		if i >= 2 && data[i-1] == '.' && isDigit(data[i-2]) || end+1 < len(data) && data[end] == '.' && isDigit(data[end+1]) {
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

		origStart, origEnd := mapOriginalRange(posMap, i, end)

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
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
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
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	if len(digits) < 2 {
		return ""
	}
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	prefix := int(digits[0]-'0')*10 + int(digits[1]-'0')

	switch {
	case prefix >= 1 && prefix <= 12:
		return abaDistrictName(prefix)
	case prefix >= 21 && prefix <= 32:
		return abaDistrictName(prefix - 20)
	case prefix >= 61 && prefix <= 72:
		return abaDistrictName(prefix - 60)
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	case prefix == 80:
		return "Traveler's Cheques"
	default:
		return ""
	}
}

// abaDistrictName returns a Federal Reserve district name.
//
//nolint:mnd // District numbers are fixed Federal Reserve identifiers.
func abaDistrictName(district int) string {
	switch district {
	case 1:
		return "01-Boston"
	case 2:
		return "02-New York"
	case 3:
		return "03-Philadelphia"
	case 4:
		return "04-Cleveland"
	case 5:
		return "05-Richmond"
	case 6:
		return "06-Atlanta"
	case 7:
		return "07-Chicago"
	case 8:
		return "08-St. Louis"
	case 9:
		return "09-Minneapolis"
	case 10:
		return "10-Kansas City"
	case 11:
		return "11-Dallas"
	case 12:
		return "12-San Francisco"
	default:
		return ""
	}
}
