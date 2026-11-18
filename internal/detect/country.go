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
	labels  []string
}

// NewCountry prepares fixed-width layouts for a country kind; unsupported names panic.
func NewCountry(name DetectorName) *Country {
	layouts, labels := countryLayouts(name)
	return &Country{name: name, layouts: layouts, labels: labels}
}

// Name identifies the selected national-number family, such as "ca_sin".
func (d *Country) Name() DetectorName { return d.name }

// Hints keeps all layouts eligible before context validation.
func (d *Country) Hints() [][]byte { return nil }

// nineDigitLayout is the unseparated layout of SSN, ITIN and SIN.
const nineDigitLayout = "#########"

// countryLayouts returns a country kind's fixed-width layouts and the label
// words that name its number, which keep a candidate under a record label
// such as ssn_id.
func countryLayouts(name DetectorName) (layouts, labels []string) {
	switch string(name) {
	case "us_ssn":
		return []string{"###-##-####", nineDigitLayout}, []string{"ssn", "security"}
	case "us_itin":
		return []string{"###-##-####", nineDigitLayout}, []string{"itin", "taxpayer"}
	case "uk_nino":
		return []string{"AA ## ## ## A", "AA######A"}, []string{"nino", "insurance"}
	case "uk_nhs":
		return []string{"### ### ####", "##########"}, []string{"nhs"}
	case "in_aadhaar":
		return []string{"#### #### ####", "############"}, []string{"aadhaar", "aadhar"}
	case "in_pan":
		return []string{"AAAAA####A"}, []string{"pan"}
	case "br_cpf":
		return []string{"###.###.###-##", "###########"}, []string{"cpf"}
	case "br_cnpj":
		return []string{"CC.CCC.CCC/CCCC-##", "CCCCCCCCCCCC##"}, []string{"cnpj"}
	case "cn_resident_id":
		return []string{"#################X"}, []string{"resident", "身份证", "身份证号"}
	case "kr_rrn":
		return []string{"######-#######", "#############"}, []string{"rrn", "주민등록번호"}
	case "ca_sin":
		return []string{"###-###-###", nineDigitLayout}, []string{"sin", "insurance"}
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
			if !ok || logContext.fragment(normalized, start, end) || recordLabeled(normalized, start, d.labels...) {
				continue
			}
			score := countryScore(d.name, value, normalized[:start])
			if score == 0 {
				continue
			}
			result = append(result, labeledViewFinding(d.name, data, positions, start, end, score))
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
		keep, ok := countryLayoutMatch(format, c)
		if !ok {
			return "", 0, false
		}
		if !keep {
			continue
		}
		value[n] = c
		n++
	}
	return string(value[:n]), end, true
}

// countryLayoutMatch reports whether c fits one layout byte and whether c is part
// of the value: '#', 'A', 'C' and 'X' are value classes, other bytes are literals.
func countryLayoutMatch(format, c byte) (keep, ok bool) {
	switch format {
	case '#':
		return true, ascii.IsDigit(c)
	case 'A':
		return true, ascii.IsUpper(c)
	case 'C':
		return true, ascii.IsDigit(c) || ascii.IsUpper(c)
	case 'X':
		return true, ascii.IsDigit(c) || c == 'X'
	default:
		return false, c == format
	}
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
	if string(name) == "kr_rrn" {
		return rrnScore(value, before)
	}
	if score, ok := countryFormatScore(string(name), value); ok {
		return score
	}
	if validCountryChecksum(string(name), value) {
		return countryChecksumScore
	}
	return 0
}

// countryFormatScore scores identifiers without a check digit, whose confidence
// comes from structure or issuing letters; ok is false for other names.
func countryFormatScore(name, value string) (score float64, ok bool) {
	var valid bool
	score = countryStructureScore
	switch name {
	case "us_ssn":
		valid = validSSN(value)
	case "us_itin":
		valid = validITIN(value)
	case "uk_nino":
		valid = validNINO(value)
		score = countryLetterScore
	case "in_pan":
		valid = validIndiaPAN(value)
		score = countryLetterScore
	default:
		return 0, false
	}
	if valid {
		return score, true
	}
	return 0, true
}

// validCountryChecksum validates identifiers whose check digit earns the
// checksum score. countryScore calls it only for the checksum families, so the
// last of them, ca_sin, is the default case.
func validCountryChecksum(name, value string) bool {
	switch name {
	case "uk_nhs":
		return validNHS(value)
	case "in_aadhaar":
		return value[0] >= '2' && !sameCountryDigits(value) && validVerhoeff(value)
	case "br_cpf":
		return validCPF(value)
	case "br_cnpj":
		return validCNPJ(value)
	case "cn_resident_id":
		return validChinaID(value)
	default:
		return value[0] != '0' && value[0] != '8' && !sameCountryDigits(value) && countryLuhn(value)
	}
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
