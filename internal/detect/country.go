package detect

import (
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

// Country implements the national-identifier contracts documented on the root Kind constants.
// See https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSSSN and the following country kinds.
type Country struct {
	name DetectorName
	countryFamily
}

// countryFamily holds everything one national number needs: its fixed-width
// layouts, the label words that name it, which keep a candidate under a record
// label such as ssn_id, whether a bare digit run needs one of those labels, and
// how a candidate value is scored.
type countryFamily struct {
	layouts []string
	labels  []string
	// bareNeedsLabel marks the kinds whose check passes about one random
	// number in ten or more, so a bare digit run alone is weak evidence.
	bareNeedsLabel bool
	// score returns 0 to reject value; before is the normalized input
	// preceding it, for families whose label can stand in for a checksum.
	score func(value string, before []byte) float64
}

// NewCountry prepares fixed-width layouts for a country kind; unsupported names panic.
func NewCountry(name DetectorName) *Country {
	family, ok := countryFamilies()[name]
	if !ok {
		panic("embargo: unsupported country kind")
	}
	return &Country{name: name, countryFamily: family}
}

// Name identifies the selected national-number family, such as "ca_sin".
func (d *Country) Name() DetectorName { return d.name }

// Hints keeps all layouts eligible before context validation.
func (d *Country) Hints() [][]byte { return nil }

// nineDigitLayout is the unseparated layout of SSN, ITIN and SIN.
const nineDigitLayout = "#########"

// countryFamilies lists every supported national number. Families without a
// check digit score their structure or issuing letters; the others score their
// checksum.
func countryFamilies() map[DetectorName]countryFamily {
	ssnLayouts := []string{"###-##-####", nineDigitLayout}
	return map[DetectorName]countryFamily{
		"us_ssn":         {ssnLayouts, []string{"ssn", "security"}, true, structureScore(validSSN, countryStructureScore)},
		"us_itin":        {ssnLayouts, []string{"itin", "taxpayer"}, true, structureScore(validITIN, countryStructureScore)},
		"uk_nino":        {[]string{"AA ## ## ## A", "AA######A"}, []string{"nino", "insurance"}, false, structureScore(validNINO, countryLetterScore)},
		"uk_nhs":         {[]string{"### ### ####", "##########"}, []string{"nhs"}, true, checksumScore(validNHS)},
		"in_aadhaar":     {[]string{"#### #### ####", "############"}, []string{"aadhaar", "aadhar"}, true, checksumScore(validAadhaar)},
		"in_pan":         {[]string{"AAAAA####A"}, []string{"pan"}, false, structureScore(validIndiaPAN, countryLetterScore)},
		"br_cpf":         {[]string{"###.###.###-##", "###########"}, []string{"cpf"}, false, checksumScore(validCPF)},
		"br_cnpj":        {[]string{"CC.CCC.CCC/CCCC-##", "CCCCCCCCCCCC##"}, []string{"cnpj"}, false, checksumScore(validCNPJ)},
		"cn_resident_id": {[]string{"#################X"}, []string{"resident", "身份证", "身份证号"}, false, checksumScore(validChinaID)},
		"kr_rrn":         {[]string{"######-#######", "#############"}, []string{"rrn", "주민등록번호"}, false, rrnScore},
		"ca_sin":         {[]string{"###-###-###", nineDigitLayout}, []string{"sin", "insurance"}, true, checksumScore(validSIN)},
	}
}

// structureScore scores a family without a check digit, whose confidence comes
// from its structure or issuing letters.
func structureScore(valid func(string) bool, score float64) func(string, []byte) float64 {
	return func(value string, _ []byte) float64 {
		if valid(value) {
			return score
		}
		return 0
	}
}

// checksumScore scores a family whose check digit earns the checksum score.
func checksumScore(valid func(string) bool) func(string, []byte) float64 {
	return structureScore(valid, countryChecksumScore)
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
			if !ok || logContext.fragment(normalized, start, end) || recordLabeled(normalized, start, d.labels...) || d.unnamedBare(normalized, start, layout) {
				continue
			}
			score := d.score(value, normalized[:start])
			if score == 0 {
				continue
			}
			result = append(result, viewFinding(d.name, positions, start, end, score))
			break
		}
	}
	return result
}

// unnamedBare reports a bare digit run of a weak kind without a label naming
// the number, such as ssn or social insurance number. SSN and ITIN have no
// check digit, and the Luhn, mod 11 and Verhoeff checks of SIN, NHS and
// Aadhaar pass one random ID in ten, so a user_id or an amount of that length
// looks the same; the separated layouts keep their own evidence.
func (d *Country) unnamedBare(data []byte, start int, layout string) bool {
	return d.bareNeedsLabel && strings.Trim(layout, "#") == "" && !labelNames(data, start, d.labels...)
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
	doubledDigit          = 2
	cnpjCycle             = 8
	rrnBodyWidth          = 12
)

func validAadhaar(value string) bool {
	return value[0] >= '2' && !sameCountryDigits(value) && validVerhoeff(value)
}

func validSIN(value string) bool {
	return value[0] != '0' && value[0] != '8' && !sameCountryDigits(value) && passesLuhn(value)
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
