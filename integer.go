package embargo

import (
	"strconv"
	"strings"

	"github.com/nao1215/embargo/internal/saferecord"
)

// exactInteger expands a valid JSON number without floating-point rounding.
// Numeric strings may include surrounding JSON whitespace, which is not part
// of the mantissa or exponent; the caller retains the original string lexeme.
// Expansion is bounded before allocating; non-integers have no second spelling.
func exactInteger(text string) (string, error) {
	mantissa, exponent, err := splitExponent(strings.Trim(text, " \t\r\n"))
	if err != nil {
		return "", err
	}
	negative := strings.HasPrefix(mantissa, "-")
	mantissa = strings.TrimPrefix(mantissa, "-")
	if dot := strings.IndexByte(mantissa, '.'); dot >= 0 {
		fraction := len(mantissa) - dot - 1
		if exponent < -maxEventBytes {
			return "", nil
		}
		exponent -= fraction
		mantissa = mantissa[:dot] + mantissa[dot+1:]
	}
	mantissa = strings.TrimLeft(mantissa, "0")
	if mantissa == "" {
		return "0", nil
	}
	if exponent < 0 {
		if exponent < -len(mantissa) {
			return "", nil
		}
		cut := len(mantissa) + exponent
		if strings.Trim(mantissa[cut:], "0") != "" {
			return "", nil
		}
		mantissa = mantissa[:cut]
	} else {
		if exponent > maxEventBytes-len(mantissa) {
			return "", saferecord.ErrSizeLimit
		}
		mantissa += strings.Repeat("0", exponent)
	}
	if negative {
		mantissa = "-" + mantissa
	}
	return mantissa, nil
}

// splitExponent separates a number lexeme into its mantissa and decimal
// exponent. An exponent outside int range is reported as a size limit.
func splitExponent(text string) (mantissa string, exponent int, err error) {
	i := strings.IndexAny(text, "eE")
	if i < 0 {
		return text, 0, nil
	}
	exponent, err = strconv.Atoi(text[i+1:])
	if err != nil {
		return "", 0, saferecord.ErrSizeLimit
	}
	return text[:i], exponent, nil
}
