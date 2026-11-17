package detect

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

// tokenSegment is one run of a provider token body. A nonzero sep must appear
// immediately before the run; max zero leaves the run unbounded. A bounded run
// that is followed by another byte of its class is rejected, so a longer
// identifier does not match a fixed-length layout.
type tokenSegment struct {
	class func(byte) bool
	min   int
	max   int
	sep   byte
}

// providerRule is a parsed provider layout: a fixed prefix, body segments, up
// to pad trailing '=' bytes and, when dotted, dot-separated routing parts.
type providerRule struct {
	prefix   string
	segments []tokenSegment
	pad      int
	dotted   bool
}

// providerLayout pairs a prefix with its body notation. The notation is a
// space-separated list of segments, each an optional separator (- . or _),
// a class letter and a length: N bytes, N-M bytes or N+ bytes. =N allows N
// padding bytes and ~ allows routing parts. Class letters are h lower-case
// hexadecimal, H hexadecimal of either case, f the Flutterwave 0-9a-h set,
// a ASCII letters and digits, A upper-case letters and digits, o lower-case
// letters and digits, l letters, n digits, t token bytes, e token bytes or =,
// d token bytes, = or dot, b base64, s base64 with _ and =, g the upper-case
// Bech32 alphabet and X the literal X.
type providerLayout struct {
	prefix string
	layout string
}

// providerLayoutTable lists provider layouts published by the providers or
// encoded in the gitleaks v8.30.0 rules, one prefix and notation per line.
// Each prefix is distinctive without a keyword. Layouts sharing a first byte
// are tried in order and the first full match wins, so a longer layout
// precedes a shorter one with the same prefix.
const providerLayoutTable = `
sk-proj- t16+
sk-svcacct- t16+
sk-ant-api03- t16+
sk-ant-admin01- t16+
sk-admin- t16+
sk- a48
sk_live_ t16+
rk_live_ t16+
whsec_ t16+
npm_ t16+
pypi- t16+
GOCSPX- t16+
glpat- t16+ ~
glcbt- t20+ ~
gldt- t20+ ~
glffct- t20+ ~
glft- t20+ ~
glimt- t20+ ~
glrt- t20+ ~
glsoat- t20+ ~
glagent- t20+ ~
gloas- t20+ ~
GR1348941 t20+ ~
glptt- h40
ops_eyJ b250+ =3
p8e- a32
AGE-SECRET-KEY-1 g58
LTAI a20
v1.0- h24 -h146
dapi h32 -n1
dapi h32
doo_v1_ h64
dop_v1_ h64
dor_v1_ h64
dp.pt. a43
duffel_test_ e43
duffel_live_ e43
dt0c01. a24 .a64
dnkey- e26 -e52
FLWSECK_TEST- f32 -X1
FLWSECK- f32 -X1
FLWSECK_TEST- f12
fio-u- e64
pat. t22 .a24 .a20
sat. t22 .a24 .a20
pat a14 .h64
s-s4t2ud- h64
s-s4t2af- h64
NRJS- h19
NRII- t32
NRAK- a27
API- A26
PMAK- h24 -h34
pnu_ a36
pul- h40
rubygems_ h48
xkeysib- h64 -a16
sntryu_ h64
sntrys_eyJ s20+ =2
sm_aat_ a16
sm_pat_ a16
sm_sat_ a16
shippo_live_ H40
shippo_test_ H40
shpat_ H32
shpca_ H32
shppa_ H32
shpss_ H32
hvs. t90-300
hvb. t138-300
SK H32
A3- A6 -A11 -A5 -A5 -A5
A3- A6 -A6 -A5 -A5 -A5 -A5
ABSK b109-269 =2
bedrock-api-key- b20+ =2
fo1_ t43
fm1a_ b100+ =3
fm1r_ b100+ =3
fm2_ b100+ =3
glc_ b32-400 =3
glsa_ a32 _H8
hf_ l34
api_org_ l34
pscale_tkn_ d32-64
pscale_oauth_ d32-64
pscale_pw_ d32-64
sgp_local_ H40
sgp_ H16 _H40
sgp_ H40
EAAM a100+
EAAC a100+
CLOJARS_ a60
EZAK a54
EZTK a54
HRKU-AA t58
pplx- a48
ntn_ a46
rdme_ o70
tk-us- t48
lin_api_ a40
ico- a32
AKCp a69
sha256~ t43
SG. t22 .t43
SG. d66
xapp- n1 -a1+ -n1+ -a32+
squ_ a40
sqp_ a40
sqa_ a40
eyJrIjoi a70-400 =3
cmVmd a59
AQVN t35-38
tfp_ d59
key- h32
access-sandbox- h8 -h4 -h4 -h4 -h12
access-development- h8 -h4 -h4 -h4 -h12
access-production- h8 -h4 -h4 -h4 -h12
`

// providerLayouts splits providerLayoutTable into prefixes and notations.
func providerLayouts() []providerLayout {
	var layouts []providerLayout
	for line := range strings.Lines(providerLayoutTable) {
		prefix, layout, _ := strings.Cut(strings.TrimSpace(line), " ")
		if prefix != "" {
			layouts = append(layouts, providerLayout{prefix: prefix, layout: layout})
		}
	}
	return layouts
}

func isLowerHexOrDigit(b byte) bool { return ascii.IsDigit(b) || (b >= 'a' && b <= 'f') }

func isBase64Byte(b byte) bool { return ascii.IsAlphaNum(b) || b == '+' || b == '/' }

func isTokenOrEquals(b byte) bool { return isTokenByte(b) || b == '=' }

// layoutClass returns the byte class of a providerLayout class letter.
func layoutClass(letter byte) func(byte) bool {
	classes := map[byte]func(byte) bool{
		'h': isLowerHexOrDigit,
		'H': ascii.IsHexDigit,
		'f': func(b byte) bool { return ascii.IsDigit(b) || (ascii.ToLower(b) >= 'a' && ascii.ToLower(b) <= 'h') },
		'a': ascii.IsAlphaNum,
		'A': func(b byte) bool { return ascii.IsUpper(b) || ascii.IsDigit(b) },
		'o': func(b byte) bool { return ascii.IsLower(b) || ascii.IsDigit(b) },
		'l': ascii.IsAlpha,
		'n': ascii.IsDigit,
		't': isTokenByte,
		'e': isTokenOrEquals,
		'd': func(b byte) bool { return isTokenOrEquals(b) || b == '.' },
		'b': isBase64Byte,
		's': func(b byte) bool { return isBase64Byte(b) || b == '_' || b == '=' },
		'g': func(b byte) bool { return strings.IndexByte("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", b) >= 0 },
		'X': func(b byte) bool { return b == 'X' },
	}
	return classes[letter]
}

// parseLayout compiles one providerLayout into a providerRule.
func parseLayout(layout providerLayout) (providerRule, error) {
	rule := providerRule{prefix: layout.prefix}
	for field := range strings.FieldsSeq(layout.layout) {
		switch {
		case field == "~":
			rule.dotted = true
		case strings.HasPrefix(field, "="):
			pad, err := strconv.Atoi(field[1:])
			if err != nil || pad < 1 {
				return rule, fmt.Errorf("layout %q: invalid padding %q", layout.prefix, field)
			}
			rule.pad = pad
		default:
			segment, err := parseSegment(field)
			if err != nil {
				return rule, fmt.Errorf("layout %q: %w", layout.prefix, err)
			}
			rule.segments = append(rule.segments, segment)
		}
	}
	if layout.prefix == "" || len(rule.segments) == 0 {
		return rule, fmt.Errorf("layout %q: a prefix and a segment are required", layout.prefix)
	}
	return rule, nil
}

var errSegmentClass = errors.New("segment needs a known class letter")

// parseSegment reads [sep]class length, where length is N, N-M or N+.
func parseSegment(field string) (tokenSegment, error) {
	var segment tokenSegment
	if field != "" && strings.IndexByte("-._", field[0]) >= 0 {
		segment.sep, field = field[0], field[1:]
	}
	if field == "" {
		return segment, errSegmentClass
	}
	if segment.class = layoutClass(field[0]); segment.class == nil {
		return segment, fmt.Errorf("%w: %q", errSegmentClass, field)
	}
	length, unbounded := strings.CutSuffix(field[1:], "+")
	low, high, ranged := strings.Cut(length, "-")
	minLen, err := strconv.Atoi(low)
	if err != nil || minLen < 1 || (unbounded && ranged) {
		return segment, fmt.Errorf("segment %q: invalid length", field)
	}
	segment.min, segment.max = minLen, minLen
	if unbounded {
		segment.max = 0
	}
	if ranged {
		if segment.max, err = strconv.Atoi(high); err != nil || segment.max < segment.min {
			return segment, fmt.Errorf("segment %q: invalid range", field)
		}
	}
	return segment, nil
}

// providerIndex buckets rules by their first prefix byte so a scan position
// only tries the rules that can start there.
type providerIndex [256][]providerRule

// newProviderIndex compiles providerLayoutTable; the layouts are fixed source
// data, so a parse error is a programming error caught by the package tests.
func newProviderIndex() *providerIndex {
	var index providerIndex
	for _, layout := range providerLayouts() {
		rule, err := parseLayout(layout)
		if err != nil {
			panic(err)
		}
		index[rule.prefix[0]] = append(index[rule.prefix[0]], rule)
	}
	return &index
}

// match returns the end of the first rule that matches at start.
func (index *providerIndex) match(data []byte, start int) (end int, ok bool) {
	for i := range index[data[start]] {
		rule := &index[data[start]][i]
		if !hasASCIIPrefix(data, start, rule.prefix) {
			continue
		}
		if end, ok := rule.bodyEnd(data, start+len(rule.prefix)); ok {
			return end, true
		}
	}
	return start, false
}

// bodyEnd matches the segments, padding and routing suffix, then requires a
// byte that cannot continue the token.
func (rule *providerRule) bodyEnd(data []byte, body int) (end int, ok bool) {
	end = body
	for _, segment := range rule.segments {
		if end, ok = segment.end(data, end); !ok {
			return end, false
		}
	}
	if placeholderBody(data[body:end]) {
		return end, false
	}
	for padded := 0; padded < rule.pad && end < len(data) && data[end] == '='; padded++ {
		end++
	}
	if rule.dotted {
		end = routingSuffixEnd(data, end)
	}
	if end < len(data) && (isTokenByte(data[end]) || (rule.pad > 0 && (isBase64Byte(data[end]) || data[end] == '='))) {
		return end, false
	}
	return end, true
}

// end matches the separator and run of one segment starting at pos.
func (segment tokenSegment) end(data []byte, pos int) (end int, ok bool) {
	if segment.sep != 0 {
		if pos >= len(data) || data[pos] != segment.sep {
			return pos, false
		}
		pos++
	}
	end = pos
	for end < len(data) && segment.class(data[end]) && (segment.max == 0 || end-pos < segment.max) {
		end++
	}
	tooLong := segment.max != 0 && end < len(data) && segment.class(data[end])
	return end, end-pos >= segment.min && !tooLong
}

// placeholderBody reports a body made of one repeated byte apart from
// separators, such as xxxx or 0000 in documentation and configuration
// templates; issued credentials are random and never take that form.
func placeholderBody(body []byte) bool {
	var first byte
	for _, b := range body {
		if b == '-' || b == '_' || b == '.' {
			continue
		}
		if first == 0 {
			first = b
		} else if b != first {
			return false
		}
	}
	return true
}

// routingSuffixEnd extends a token over dot-separated ASCII letter or digit
// parts, which routable GitLab tokens append after the random body.
func routingSuffixEnd(data []byte, pos int) int {
	for pos+1 < len(data) && data[pos] == '.' && ascii.IsAlphaNum(data[pos+1]) {
		next := pos + 1
		for next < len(data) && ascii.IsAlphaNum(data[next]) {
			next++
		}
		pos = next
	}
	return pos
}
