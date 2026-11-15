package detect

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Independent finite alphabets target boundary mutants missed by ordinary prose.
func TestDetectorByteAlphabets(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		alnum := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", rune(b))
		if isLocalPartChar(b) != (alnum || strings.ContainsRune(".+-_", rune(b))) {
			t.Fatalf("local alphabet %x", b)
		}
		if isDomainChar(b) != (alnum || strings.ContainsRune(".-", rune(b))) {
			t.Fatalf("domain alphabet %x", b)
		}
		_, err := hex.DecodeString("0" + string(b))
		if isHexChar(b) != (err == nil) {
			t.Fatalf("hex alphabet %x", b)
		}
		if toLowerASCIIString(string(b)) != string(bytes.ToLower([]byte{b})) && b < 128 {
			t.Fatalf("case endpoint %x", b)
		}
	}
	for _, domain := range []string{"", "a", "-a", "a-b", "a-.b", "a.-b", "a.b", "a..b", ".a", "a."} {
		want := false
		for label := range strings.SplitSeq(domain, ".") {
			want = want || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-")
		}
		// The helper's contract only covers leading '-' and '-' adjacent to dots;
		// trailing domain hyphens are removed by findDomainEnd.
		if hasInvalidLabelBoundary([]byte(domain)) != want {
			t.Fatalf("label boundary %q", domain)
		}
		if hasConsecutiveDots([]byte(domain)) != strings.Contains(domain, "..") {
			t.Fatalf("dots %q", domain)
		}
	}
}

func TestNormalizationIdentityDifferential(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		input := append([]byte("４２４２ "), byte(n))
		for _, data := range [][]byte{input, {byte(n)}, []byte("4242424242424242"), nil} {
			want, indices := NormalizeFullWidthDigits(data)
			got, positions := normalizeDigits(data)
			if !bytes.Equal(got, want) {
				t.Fatal("normalization differs")
			}
			for i := 0; i <= len(got); i++ {
				if originalPosition(positions, i) != indices[i] {
					t.Fatal("position differs")
				}
			}
		}
	}
}

func TestCredentialAndNetworkAlphabetEdges(t *testing.T) {
	t.Parallel()
	for n := range 256 {
		b := byte(n)
		upper := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", rune(b))
		alnum := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", rune(b))
		if isUpperAlphaNum(b) != upper || isBase62(b) != alnum {
			t.Fatalf("credential byte %x", b)
		}
		if isTokenChar(b) != (alnum || strings.ContainsRune("_-", rune(b))) {
			t.Fatalf("payment byte %x", b)
		}
		if isBase58Char(b) != strings.ContainsRune("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", rune(b)) {
			t.Fatalf("base58 byte %x", b)
		}
		_, err := hex.DecodeString("0" + string(b))
		if isHexDigit(b) != (err == nil) {
			t.Fatalf("IP hex %x", b)
		}
		if toUpperByte(b) != bytes.ToUpper([]byte{b})[0] && b < 128 {
			t.Fatalf("uppercase %x", b)
		}
	}
	for _, s := range []string{"aA", "fF", "aF", "fA", "09af", "09AF"} {
		want := hexCaseMixed
		if s == strings.ToLower(s) || s == strings.ToUpper(s) {
			want = hexCaseUniform
		}
		if hexCaseType(s) != want {
			t.Fatalf("hex case %q", s)
		}
	}
}

func TestCredentialMinimumLengths(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d      Detector
		prefix string
		min    int
	}{
		{NewGitHubToken(), "github_pat_", 22},
		{NewSlackToken(), "xoxb-", 10},
		{NewPaymentToken(), "sk_test_", 16},
		{NewPaymentToken(), "tok_", 8},
	} {
		for _, n := range []int{tc.min - 1, tc.min, tc.min + 1} {
			raw := tc.prefix + strings.Repeat("a", n)
			got := tc.d.Scan([]byte(raw + " " + raw))
			if n < tc.min {
				if len(got) != 0 {
					t.Fatal(tc.prefix, n, got)
				}
				continue
			}
			if len(got) != 2 || got[0].Start != 0 || got[0].End != len(raw) || got[1].Start != len(raw)+1 || got[1].End != 2*len(raw)+1 {
				t.Fatal(tc.prefix, n, got)
			}
		}
	}
}

func TestPANPrefixAndLengthEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		prefix string
		brand  CardBrand
	}{
		{"51", BrandMastercard},
		{"55", BrandMastercard},
		{"50", ""},
		{"56", ""},
		{"3527", ""},
		{"3528", BrandJCB},
		{"3589", BrandJCB},
		{"3590", ""},
		{"643", ""},
		{"644", BrandDiscover},
		{"649", BrandDiscover},
		{"650", BrandDiscover},
	} {
		raw := tc.prefix + strings.Repeat("0", 16-len(tc.prefix))
		got := NewPAN().Scan([]byte(raw))
		if tc.brand == "" {
			if len(got) != 0 {
				t.Fatal(tc.prefix, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Fatal(tc.prefix, got)
		}
		detail, ok := got[0].Detail.(*PANDetail)
		if !ok || detail.Brand != tc.brand {
			t.Fatal(tc.prefix, got)
		}
	}
	for _, n := range []int{15, 16, 19, 20} {
		if isExpectedLength(BrandUnionPay, n) != (n == 16 || n == 19) {
			t.Fatal("UnionPay length", n)
		}
	}
}

func TestPhoneConfidenceAndContainsEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw        string
		confidence float64
	}{{"090-1234-5678", .9}, {"03-1234-5678", .8}} {
		got := NewJPPhone().Scan([]byte(tc.raw))
		if len(got) != 1 || got[0].Confidence != tc.confidence {
			t.Fatal(tc.raw, got)
		}
	}
	for _, data := range []string{"", "a", "aa", "abc"} {
		for _, sub := range []string{"", "a", "aa", "abc", "abcd"} {
			if containsBytes([]byte(data), []byte(sub)) != strings.Contains(data, sub) {
				t.Fatal("contains", data, sub)
			}
		}
	}
	if bankAccountKeywordLang(nil) != BankAccountLangEN || bankAccountKeywordLang([]byte{0x80}) != BankAccountLangJA {
		t.Fatal("keyword language")
	}
}

func TestAdjacentCandidatesAndChecksumRemainder(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d    Detector
		text string
		want int
	}{
		{NewABARouting(), "021000021;021000021", 2},
		{NewABARouting(), "123;021000021", 1},
		{NewCardExpiry(), "expiry 12/29;01/30", 2},
		{NewMyNumber(), "000000000060", 1},
	} {
		if got := tc.d.Scan([]byte(tc.text)); len(got) != tc.want {
			t.Fatal(tc.d.Name(), tc.text, got)
		}
	}
}

func TestContextCanFollowSensitiveValue(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d    Detector
		text string
		end  int
	}{
		{NewCVV(), "123 CVV", 3},
		{NewBankAccount(), "12345678 bank account", 8},
		{NewACHTrace(), "021000021123456 ACH trace", 15},
		{NewMerchantID(), "ABCDE12345FGHI6 merchant ID", 15},
	} {
		got := tc.d.Scan([]byte(tc.text))
		if len(got) != 1 || got[0].Start != 0 || got[0].End != tc.end {
			t.Fatal(tc.d.Name(), got)
		}
	}
}

func TestBusinessLabelsAtFieldBoundaries(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"[Order ID: ", ";invoice=", "\ntracking: ", "{\"serial\":\""} {
		got := NewPAN().Scan([]byte(prefix + "4242424242424242"))
		if len(got) != 1 || got[0].Confidence != .4 {
			t.Fatal(prefix, got)
		}
	}
}
