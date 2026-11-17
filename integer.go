package embargo

import (
	"strconv"
	"strings"

	"github.com/nao1215/embargo/internal/saferecord"
)

// exactInteger expands a valid JSON number without floating-point rounding.
// Expansion is bounded before allocating; non-integers have no second spelling.
func exactInteger(text string) (string, error) {
	mantissa, exponent := text, 0
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		mantissa = text[:i]
		value, err := strconv.Atoi(text[i+1:])
		if err != nil {
			return "", saferecord.ErrSizeLimit
		}
		exponent = value
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
