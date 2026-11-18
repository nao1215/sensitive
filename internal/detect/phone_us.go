package detect

import "github.com/nao1215/embargo/internal/ascii"

// USPhone implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSPhone.
type USPhone struct{}

// NewUSPhone recognizes separated ten-digit North American numbers.
func NewUSPhone() *USPhone {
	return &USPhone{}
}

// Name returns "phone_us".
func (d *USPhone) Name() DetectorName {
	return NameUSPhone
}

// Hints returns the pre-filter substrings for [USPhone]: an area code starts
// with 2 through 9 or an opening parenthesis.
func (d *USPhone) Hints() [][]byte {
	return [][]byte{[]byte("2"), []byte("3"), []byte("4"), []byte("5"), []byte("6"), []byte("7"), []byte("8"), []byte("9"), []byte("(")}
}

// Layout of a separated number: a three-digit code, one separator, and a
// four-digit line; a parenthesized area code spans five bytes.
const (
	usPhoneDigits     = 10
	usPhoneCodeLength = 3
	usPhoneLine       = 4
	usPhoneLineEnd    = usPhoneCodeLength + 1 + usPhoneLine
	usPhoneParenArea  = usPhoneCodeLength + 2
	usPhoneCountry    = len("1 ")
)

// Scan returns matches in data using the rules documented on [USPhone].
func (d *USPhone) Scan(data []byte) []Finding {
	if !hasDigits(data, usPhoneDigits) || !hasDigitRun(data, usPhoneLine) {
		return nil
	}
	var findings []Finding
	for i := 0; i < len(data); i++ {
		if !usPhoneStart(data[i]) {
			continue
		}
		end, ok := usPhoneAt(data, i)
		if !ok {
			continue
		}
		start := usPhoneCountryCode(data, i)
		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        start,
			End:          end,
			Confidence:   businessConfidence(data, start, usPhoneConfidence(data, start)),
		})
		i = end - 1
	}
	return findings
}

// usPhoneStart reports whether b can open a number: an area code digit 2–9
// or an opening parenthesis.
func usPhoneStart(b byte) bool {
	return b == '(' || (b >= '2' && b <= '9')
}

// usPhoneAt matches (202) 555-0123, 202-555-0123, 202.555.0123 or 202 555 0123
// shapes starting at i and returns its end. Separators are required, so bare digit
// runs such as IDs and timestamps are not phone numbers.
func usPhoneAt(data []byte, i int) (int, bool) {
	if !usPhoneLeadingBoundary(data, i) {
		return 0, false
	}
	exchange, ok := usPhoneAreaCode(data, i)
	if !ok || exchange+usPhoneLineEnd > len(data) {
		return 0, false
	}
	separator := data[exchange+usPhoneCodeLength]
	if !usPhoneExchange(data[exchange:exchange+usPhoneCodeLength]) || (separator != '-' && separator != '.' && separator != ' ') || !allDigits(data[exchange+usPhoneCodeLength+1:exchange+usPhoneLineEnd]) {
		return 0, false
	}
	end := exchange + usPhoneLineEnd
	return end, usPhoneTrailingBoundary(data, end)
}

// usPhoneAreaCode accepts a parenthesized or plain area code at i and returns
// where the exchange starts. A plain area code must use the same separator as
// the exchange, so 202-555.0123 is rejected.
func usPhoneAreaCode(data []byte, i int) (int, bool) {
	if data[i] == '(' {
		if i+usPhoneParenArea > len(data) || !usPhoneArea(data[i+1:i+1+usPhoneCodeLength]) || data[i+usPhoneParenArea-1] != ')' {
			return 0, false
		}
		next := i + usPhoneParenArea
		if next < len(data) && data[next] == ' ' {
			next++
		}
		return next, next+usPhoneCodeLength < len(data) && data[next+usPhoneCodeLength] == '-'
	}
	if i+usPhoneCodeLength >= len(data) || !usPhoneArea(data[i:i+usPhoneCodeLength]) {
		return 0, false
	}
	separator := data[i+usPhoneCodeLength]
	if separator != '-' && separator != '.' && separator != ' ' {
		return 0, false
	}
	next := i + usPhoneCodeLength + 1
	return next, next+usPhoneCodeLength < len(data) && data[next+usPhoneCodeLength] == separator
}

// usPhoneArea checks a North American area code: 2–9, then 0–8, then a digit.
func usPhoneArea(code []byte) bool {
	return allDigits(code) && code[0] >= '2' && code[1] != '9'
}

// usPhoneExchange checks a central office code: 2–9 first and not an N11
// service code such as 911.
func usPhoneExchange(code []byte) bool {
	return allDigits(code) && code[0] >= '2' && (code[1] != '1' || code[2] != '1')
}

// usPhoneLeadingBoundary rejects a candidate inside an identifier, a longer
// number, a dotted version or a path. An opening parenthesis is itself a
// boundary, so "x(212) 555-0100" and a number glued to a previous number match.
func usPhoneLeadingBoundary(data []byte, i int) bool {
	if i == 0 {
		return true
	}
	previous := data[i-1]
	if previous == '-' || previous == '.' {
		// Only a 1 or +1 country code may join the number with these separators.
		return usPhoneCountryCode(data, i) != i
	}
	return (data[i] == '(' || !isIdentifierByte(previous)) && previous != '/' && previous != '+'
}

// usPhoneTrailingBoundary rejects a candidate followed by more digits or a
// separator that continues the number.
func usPhoneTrailingBoundary(data []byte, end int) bool {
	if end == len(data) {
		return true
	}
	next := data[end]
	if isIdentifierByte(next) {
		return false
	}
	continues := next == '-' || next == '.' || next == '/'
	return !continues || end+1 == len(data) || !ascii.IsDigit(data[end+1])
}

// usPhoneCountryCode extends the start over a preceding +1 or 1 with a
// separator, so the country code is masked with the number.
func usPhoneCountryCode(data []byte, start int) int {
	if start < usPhoneCountry || (data[start-1] != ' ' && data[start-1] != '-' && data[start-1] != '.') || data[start-usPhoneCountry] != '1' {
		return start
	}
	code := start - usPhoneCountry
	if code > 0 && data[code-1] == '+' {
		code--
	}
	if code > 0 && (isIdentifierByte(data[code-1]) || data[code-1] == '.' || data[code-1] == '-') {
		return start
	}
	return code
}

// usPhoneConfidence scores a number 0.7, or 0.9 after a phone label such as
// phone, tel, mobile or fax.
func usPhoneConfidence(data []byte, start int) float64 {
	prefix := labelPrefix(data, start)
	for range 3 {
		var word []byte
		prefix, word = previousLabelWord(prefix)
		if labelIs(word, "phone", "tel", "telephone", "mobile", "cell", "fax", "call", "contact") {
			//nolint:mnd // Labeled phone numbers carry the documented higher score.
			return 0.9
		}
		if len(prefix) == 0 {
			break
		}
	}
	//nolint:mnd // Unlabeled separated numbers carry the documented base score.
	return 0.7
}
