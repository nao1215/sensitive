package detect

import "bytes"

// labelPrefix confines contextual evidence to the current field and line.
func labelPrefix(data []byte, start int) []byte {
	const radius = 48
	prefix := data[max(0, start-radius):start]
	if i := bytes.LastIndexAny(prefix, "\r\n;,{}[]?&"); i >= 0 {
		prefix = prefix[i+1:]
	}
	return prefix
}

// previousLabelWord returns slices of the input, without allocating on every finding.
func previousLabelWord(prefix []byte) (rest, word []byte) {
	end := len(prefix)
	for end > 0 && labelSeparator(prefix[end-1]) {
		end--
	}
	start := end
	for start > 0 && !labelSeparator(prefix[start-1]) {
		start--
	}
	return prefix[:start], prefix[start:end]
}

func labelSeparator(b byte) bool {
	switch b {
	case ' ', '\t', ':', '=', '_', '-', '"', '\'':
		return true
	default:
		return false
	}
}

func labelIs(word []byte, values ...string) bool {
	for _, value := range values {
		if bytes.EqualFold(word, []byte(value)) {
			return true
		}
	}
	return false
}

// ambiguousConfidence is the score of a number whose shape is valid but whose
// label names a record, such as a card number under order_id.
const ambiguousConfidence = .4

// labelWords is how many label words before a candidate can name its number,
// as in social security number.
const labelWords = 3

// phoneLabels returns the words that name a telephone number.
func phoneLabels() []string {
	return []string{"phone", "tel", "telephone", "mobile", "cell", "fax", "call", "contact", "電話", "携帯"}
}

// recordConfidence lowers a number under a record label, as recordLabeled
// decides, to ambiguousConfidence. The number stays reported, because a
// payment card or a phone number under a field such as user_id is still one.
func recordConfidence(data []byte, start int, confidence float64, own ...string) float64 {
	if recordLabeled(data, start, own...) {
		return ambiguousConfidence
	}
	return confidence
}

// labelNames reports whether one of the label words right before start names
// the number: an ASCII word equal to one in own, ignoring case, or a non-ASCII
// word containing a non-ASCII one, as 電話番号 contains 電話.
func labelNames(data []byte, start int, own ...string) bool {
	prefix := labelPrefix(data, start)
	for range labelWords {
		var word []byte
		prefix, word = previousLabelWord(prefix)
		if ownWord(word, own) {
			return true
		}
		if len(prefix) == 0 {
			return false
		}
	}
	return false
}

func ownWord(word []byte, own []string) bool {
	if labelIs(word, own...) {
		return true
	}
	if !hasNonASCII(word) {
		return false
	}
	for _, label := range own {
		if hasNonASCII([]byte(label)) && bytes.Contains(word, []byte(label)) {
			return true
		}
	}
	return false
}

// japaneseBusinessLabel reports whether a label written in Japanese names an
// order, invoice, shipment, product or version, such as 注文番号 or 品番. Japanese
// text puts no space before the label, so any word containing a stem counts.
func japaneseBusinessLabel(word []byte) bool {
	if !hasNonASCII(word) {
		return false
	}
	for _, stem := range []string{"注文", "請求", "追跡", "伝票", "配送", "問い合わせ", "問合せ", "受付", "予約", "型番", "品番", "製造", "シリアル", "商品", "バージョン"} {
		if bytes.Contains(word, []byte(stem)) {
			return true
		}
	}
	return false
}

// identifierLabeled reports whether the label attached to start names a
// record identifier, such as accountId, user_id, account, tracking or 注文番号,
// rather than a My Number. Twelve-digit account and record IDs pass the My
// Number check digit about one time in ten, so such a label rules the
// candidate out. A My Number label (My Number, mynumber, individual number,
// マイナンバー or 個人番号) always keeps it.
func identifierLabeled(data []byte, start int) bool {
	rest, word := previousLabelWord(labelPrefix(data, start))
	switch {
	case len(word) == 0, myNumberLabel(word):
		return false
	case labelIs(word, "number", "no", "num"):
		_, previous := previousLabelWord(rest)
		return !labelIs(previous, "my", "individual", "kojin")
	}
	return recordWord(word)
}

// recordLabeled reports whether the label attached to start names a record
// identifier rather than the number a detector checks, so a check digit that
// a random ID passes by chance does not mask it: a record word, or number, no
// or num after one (order number). own lists the words that name the
// detector's number; as one of the label words before start, as in routing
// code or ssn_id, they keep the candidate.
func recordLabeled(data []byte, start int, own ...string) bool {
	if labelNames(data, start, own...) {
		return false
	}
	rest, word := previousLabelWord(labelPrefix(data, start))
	switch {
	case len(word) == 0:
		return false
	case labelIs(word, "number", "no", "num"):
		_, previous := previousLabelWord(rest)
		return recordWord(previous)
	}
	return recordWord(word)
}

// recordWord reports one label word that names a record: a word ending in id
// or ID, account, user, order and similar record words, or a Japanese word
// containing 番号 or a business stem.
func recordWord(word []byte) bool {
	switch {
	case len(word) >= len("id") && labelIs(word[len(word)-len("id"):], "id"):
		return true
	case labelIs(word, "account", "acct", "user", "customer", "member", "order", "invoice", "tracking", "serial", "version", "build", "shipment", "ref", "code", "request", "trace", "transaction", "ticket", "job"):
		return true
	}
	return japaneseBusinessLabel(word) || bytes.Contains(word, []byte("番号"))
}

// myNumberLabel reports whether one label word names a My Number.
func myNumberLabel(word []byte) bool {
	return labelIs(word, "mynumber", "kojinbango") || bytes.Contains(word, []byte("マイナンバー")) || bytes.Contains(word, []byte("個人番号"))
}

// hasNonASCII reports whether word has a byte outside ASCII, so ASCII labels
// skip the Japanese stem search.
func hasNonASCII(word []byte) bool {
	for _, b := range word {
		if b&0x80 != 0 {
			return true
		}
	}
	return false
}
