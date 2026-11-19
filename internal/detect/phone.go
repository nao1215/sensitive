package detect

import (
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

// Phone implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindPhone.
type Phone struct {
	codes map[string]bool
}

// NewPhone recognizes international numbers written with + and a country calling code.
func NewPhone() *Phone {
	codes := make(map[string]bool)
	for code := range strings.FieldsSeq(callingCodes) {
		codes[code] = true
	}
	return &Phone{codes: codes}
}

// Name returns "phone".
func (d *Phone) Name() DetectorName {
	return NamePhone
}

// Hints returns the pre-filter substring for [Phone]: every number starts with +.
func (d *Phone) Hints() [][]byte {
	return [][]byte{[]byte("+")}
}

// E.164 limits: a number has at most 15 digits including its country code.
// The shortest assigned numbers, such as those of Niue (+683), have seven.
// Without separators a short run reads like a signed amount (+1000000), so an
// unseparated number needs ten digits.
const (
	phoneMinDigits         = 7
	phoneMaxDigits         = 15
	phoneMinBareDigits     = 10
	phoneMinSubscriber     = 4
	phoneMaxCountryCode    = 3
	phoneMaxParenDigits    = 4
	phoneLabeledConfidence = 0.9
	phoneBaseConfidence    = 0.8
)

// Scan returns matches in data using the rules documented on [Phone].
func (d *Phone) Scan(data []byte) []Finding {
	var findings []Finding
	previousEnd := -1
	for i := 0; i < len(data); i++ {
		// A number that directly follows another, as after a removed no-break
		// space, starts at the previous end even though a digit precedes it.
		if data[i] != '+' || (i != previousEnd && !phoneLeadingBoundary(data, i)) {
			continue
		}
		end, ok := d.phoneAt(data, i+1)
		if !ok {
			continue
		}
		confidence := phoneBaseConfidence
		if labelNames(data, i, phoneLabels()...) {
			confidence = phoneLabeledConfidence
		}
		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			Confidence:   recordConfidence(data, i, confidence, phoneLabels()...),
		})
		previousEnd = end
		i = end - 1
	}
	return findings
}

// phoneLeadingBoundary rejects a + inside an identifier, after a digit, as in
// a timestamp offset 10:00+09:00, or after another +.
func phoneLeadingBoundary(data []byte, i int) bool {
	return i == 0 || (!isIdentifierByte(data[i-1]) && data[i-1] != '+')
}

// phoneAt reads a country calling code at start, followed by digit groups
// separated by one space, hyphen or dot, and returns the end of the number.
func (d *Phone) phoneAt(data []byte, start int) (int, bool) {
	code := d.countryCode(data, start)
	if code == 0 {
		return 0, false
	}
	end, subscriber, separated, ok := phoneSubscriber(data, start+code, phoneMaxDigits-code)
	if !ok || !phoneLength(code, subscriber, separated) {
		return 0, false
	}
	return end, phoneTrailingBoundary(data, end)
}

// phoneSubscriber reads the digit groups after the country code and returns
// where they end, their digits without a trunk prefix, and whether a
// separator or parenthesis appeared. ok is false past limit digits.
func phoneSubscriber(data []byte, end, limit int) (next int, subscriber []byte, separated, ok bool) {
	for at := end; ; at = end {
		separator := at < len(data) && (data[at] == ' ' || data[at] == '-' || data[at] == '.')
		if separator {
			at++
		}
		groupEnd, digits, trunk, found := phoneGroup(data, at)
		if !found {
			return end, subscriber, separated, true
		}
		separated = separated || separator || data[at] == '('
		if !trunk {
			subscriber = append(subscriber, digits...)
		}
		if len(subscriber) > limit {
			return 0, nil, false, false
		}
		end = groupEnd
	}
}

// phoneLength applies the E.164 digit limits and rejects a placeholder of
// one repeated digit.
func phoneLength(code int, subscriber []byte, separated bool) bool {
	total := code + len(subscriber)
	return len(subscriber) >= phoneMinSubscriber && total >= phoneMinDigits && (separated || total >= phoneMinBareDigits) && !sameDigits(subscriber)
}

// phoneGroup reads one digit run at at, or a parenthesized group of up to
// four digits such as the area code in +1 (202) 555-0123. A parenthesized 0 is
// the trunk prefix of +44 (0)20 7946 0958, dialed only inside the country.
func phoneGroup(data []byte, at int) (next int, digits []byte, trunk, ok bool) {
	if at < len(data) && data[at] == '(' {
		closing := at + 1
		for closing < len(data) && closing-at <= phoneMaxParenDigits && ascii.IsDigit(data[closing]) {
			closing++
		}
		if closing == at+1 || closing >= len(data) || data[closing] != ')' {
			return 0, nil, false, false
		}
		digits = data[at+1 : closing]
		return closing + 1, digits, string(digits) == "0", true
	}
	next = at
	for next < len(data) && ascii.IsDigit(data[next]) {
		next++
	}
	return next, data[at:next], false, next > at
}

// countryCode returns the length of the assigned calling code at start,
// or 0. Calling codes are prefix-free, so at most one length matches.
func (d *Phone) countryCode(data []byte, start int) int {
	for n := 1; n <= phoneMaxCountryCode && start+n <= len(data); n++ {
		if !ascii.IsDigit(data[start+n-1]) {
			return 0
		}
		if d.codes[string(data[start:start+n])] {
			return n
		}
	}
	return 0
}

// callingCodes lists the ITU-T E.164 country calling codes in service,
// including global services such as 800 and 883. Spare and reserved codes are
// absent, so +0 and +28 never start a number.
const callingCodes = `
1 7 20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 51 52 53 54 55 56 57 58 60 61 62 63
64 65 66 81 82 84 86 90 91 92 93 94 95 98 211 212 213 216 218 220 221 222 223 224 225 226 227
228 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 250
251 252 253 254 255 256 257 258 260 261 262 263 264 265 266 267 268 269 290 291 297 298 299
350 351 352 353 354 355 356 357 358 359 370 371 372 373 374 375 376 377 378 379 380 381 382
383 385 386 387 389 420 421 423 500 501 502 503 504 505 506 507 508 509 590 591 592 593 594
595 596 597 598 599 670 672 673 674 675 676 677 678 679 680 681 682 683 685 686 687 688 689
690 691 692 800 808 850 852 853 855 856 870 880 881 882 883 886 960 961 962 963 964 965 966
967 968 970 971 972 973 974 975 976 977 979 992 993 994 995 996 998
`

// phoneTrailingBoundary rejects a number that runs into an identifier, more
// digits, or a dotted or slashed continuation such as a version or a date.
func phoneTrailingBoundary(data []byte, end int) bool {
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

// sameDigits reports a run of one repeated digit, such as 0000000, which is a
// placeholder rather than a subscriber number.
func sameDigits(digits []byte) bool {
	for _, d := range digits {
		if d != digits[0] {
			return false
		}
	}
	return true
}
