package detect

import (
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

// Country implements the national-identifier contracts documented on the root Kind constants.
// See https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSSSN and the following country kinds.
type Country struct {
	name    DetectorName
	layouts []string
}

// NewCountry prepares fixed-width layouts for a country kind; unsupported names panic.
func NewCountry(name DetectorName) *Country {
	return &Country{name: name, layouts: countryLayouts(name)}
}

// Name identifies the selected national-number family, such as "ca_sin".
func (d *Country) Name() DetectorName { return d.name }

// Hints keeps all layouts eligible before context validation.
func (d *Country) Hints() [][]byte { return nil }

func countryLayouts(name DetectorName) []string {
	switch string(name) {
	case "us_ssn", "us_itin":
		return []string{"###-##-####", "#########"}
	case "uk_nino":
		return []string{"AA ## ## ## A", "AA######A"}
	case "uk_nhs":
		return []string{"### ### ####", "##########"}
	case "in_aadhaar":
		return []string{"#### #### ####", "############"}
	case "in_pan":
		return []string{"AAAAA####A"}
	case "br_cpf":
		return []string{"###.###.###-##", "###########"}
	case "br_cnpj":
		return []string{"CC.CCC.CCC/CCCC-##", "CCCCCCCCCCCC##"}
	case "cn_resident_id":
		return []string{"#################X"}
	case "kr_rrn":
		return []string{"######-#######", "#############"}
	case "ca_sin":
		return []string{"###-###-###", "#########"}
	default:
		panic("embargo: unsupported country kind")
	}
}

// Scan maps normalized digits back to byte ranges and rejects candidates embedded in identifiers.
func (d *Country) Scan(data []byte) []Finding {
	normalized, positions := normalizeDigits(data)
	var result []Finding
	var logContext numericLogContext
	for start := range normalized {
		if start > 0 && isIdentifierByte(normalized[start-1]) {
			continue
		}
		for _, layout := range d.layouts {
			value, end, ok := countryCandidate(normalized, start, layout)
			if !ok || logContext.fragment(normalized, start, end) {
				continue
			}
			score := countryScore(d.name, value, normalized[:start])
			if score == 0 {
				continue
			}
			a, b := mapOriginalRange(positions, start, end)
			result = append(result, Finding{DetectorName: d.name, Start: a, End: b, Confidence: businessConfidence(data, a, score)})
			break
		}
	}
	return result
}

func countryCandidate(data []byte, start int, layout string) (text string, end int, ok bool) {
	end = start + len(layout)
	if end > len(data) || (end < len(data) && isIdentifierByte(data[end])) {
		return "", 0, false
	}
	var value [18]byte
	n := 0
	for i, format := range []byte(layout) {
		c := data[start+i]
		switch format {
		case '#':
			if !ascii.IsDigit(c) {
				return "", 0, false
			}
		case 'A':
			if c < 'A' || c > 'Z' {
				return "", 0, false
			}
		case 'C':
			if !ascii.IsDigit(c) && (c < 'A' || c > 'Z') {
				return "", 0, false
			}
		case 'X':
			if !ascii.IsDigit(c) && c != 'X' {
				return "", 0, false
			}
		default:
			if c != format {
				return "", 0, false
			}
			continue
		}
		value[n] = c
		n++
	}
	return string(value[:n]), end, true
}

const (
	countryChecksumScore  = 0.95
	countryLetterScore    = 0.7
	countryStructureScore = 0.6
	decimalRadix          = 10
	mod11Base             = 11
	luhnCorrection        = 9
	doubledDigit          = 2
	cnpjCycle             = 8
	rrnBodyWidth          = 12
)

func countryScore(name DetectorName, value string, before []byte) float64 {
	valid := false
	score := countryChecksumScore
	switch string(name) {
	case "us_ssn":
		valid = validSSN(value)
		score = countryStructureScore
	case "us_itin":
		valid = validITIN(value)
		score = countryStructureScore
	case "uk_nino":
		valid = validNINO(value)
		score = countryLetterScore
	case "in_pan":
		valid = validIndiaPAN(value)
		score = countryLetterScore
	case "uk_nhs":
		valid = validNHS(value)
	case "in_aadhaar":
		valid = value[0] >= '2' && !sameCountryDigits(value) && validVerhoeff(value)
	case "br_cpf":
		valid = validCPF(value)
	case "br_cnpj":
		valid = validCNPJ(value)
	case "cn_resident_id":
		valid = validChinaID(value)
	case "ca_sin":
		valid = value[0] != '0' && value[0] != '8' && !sameCountryDigits(value) && countryLuhn(value)
	case "kr_rrn":
		return rrnScore(value, before)
	}
	if valid {
		return score
	}
	return 0
}

func sameCountryDigits(value string) bool { return strings.Count(value, value[:1]) == len(value) }

func rrnScore(value string, before []byte) float64 {
	if !validRRNDate(value) {
		return 0
	}
	sum := 0
	for i := range 12 {
		sum += int(value[i]-'0') * (doubledDigit + i%cnpjCycle)
	}
	if (mod11Base-sum%mod11Base)%decimalRadix == int(value[12]-'0') {
		return countryChecksumScore
	}
	label := strings.TrimRight(string(labelPrefix(before, len(before))), " \t:=\"'")
	for _, key := range []string{"rrn", "주민등록번호"} {
		if strings.HasSuffix(strings.ToLower(label), key) {
			pos := len(label) - len(key)
			if pos == 0 || !isIdentifierByte(label[pos-1]) {
				return countryStructureScore
			}
		}
	}
	return 0
}
