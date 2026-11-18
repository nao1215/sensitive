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

// businessConfidence preserves ambiguous numbers for callers that favor recall.
// Only an attached business label lowers confidence, never a remote keyword.
func businessConfidence(data []byte, start int, confidence float64) float64 {
	prefix := labelPrefix(data, start)
	for len(prefix) > 0 {
		rest, word := previousLabelWord(prefix)
		prefix = rest
		if labelIs(word, "id", "number", "ref", "code") {
			continue
		}
		if labelIs(word, "order", "invoice", "tracking", "version", "build", "serial", "shipment") || japaneseBusinessLabel(word) {
			const ambiguousConfidence = .4
			return ambiguousConfidence
		}
		break
	}
	return confidence
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
	case len(word) >= len("id") && labelIs(word[len(word)-len("id"):], "id"):
		return true
	case labelIs(word, "account", "acct", "user", "customer", "member", "order", "invoice", "tracking", "serial", "version", "build", "shipment", "ref", "code", "request", "trace", "transaction", "ticket", "job"):
		return true
	}
	return japaneseBusinessLabel(word) || bytes.Contains(word, []byte("番号")) || bytes.HasSuffix(word, []byte("ID"))
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
