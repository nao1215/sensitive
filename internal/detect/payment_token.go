package detect

// PaymentToken implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindPaymentToken.
type PaymentToken struct{}

// NewPaymentToken recognizes payment-provider prefixes without authenticating the tokens.
func NewPaymentToken() *PaymentToken {
	return &PaymentToken{}
}

// Name returns "payment_token".
func (d *PaymentToken) Name() DetectorName {
	return NamePaymentToken
}

// Hints returns the pre-filter substrings for [PaymentToken].
func (d *PaymentToken) Hints() [][]byte {
	return [][]byte{
		[]byte("sk_live_"),
		[]byte("pk_live_"),
		[]byte("sk_test_"),
		[]byte("pk_test_"),
		[]byte("tok_"),
		[]byte("pi_"),
		[]byte("pm_"),
		[]byte("cus_"),
		[]byte("sub_"),
		[]byte("price_"),
		[]byte("prod_"),
		[]byte("PAYID-"),
		[]byte("sq0idp-"),
		[]byte("sq0csp-"),
	}
}

// Scan returns matches in data using the rules documented on [PaymentToken].
func (d *PaymentToken) Scan(data []byte) []Finding {
	var findings []Finding
	patterns := tokenPatterns()

	for i := 0; i < len(data); i++ {
		// Word boundary: preceding character must not be alphanumeric or underscore.
		if i > 0 && isIdentifierByte(data[i-1]) && !encodedSeparatorBefore(data, i) {
			continue
		}

		end := paymentTokenEnd(data, i, patterns)
		if end < 0 {
			continue
		}
		findings = append(findings, Finding{
			DetectorName: d.Name(),
			Start:        i,
			End:          end,
			//nolint:mnd // The detector contract documents this heuristic score.
			Confidence: 0.9,
		})

		i = end - 1 // Move to next position after matching.
	}

	return findings
}

// paymentTokenEnd returns the end of the token at i for the first pattern, in
// list order, whose prefix and minimum body length match, or -1 when none does.
func paymentTokenEnd(data []byte, i int, patterns []tokenPattern) int {
	for _, pattern := range patterns {
		if end := paymentPatternEnd(data, i, pattern); end >= 0 {
			return end
		}
	}
	return -1
}

// paymentPatternEnd matches one pattern's prefix at i and returns the end of
// its token body, or -1 when the prefix differs or the body is too short.
func paymentPatternEnd(data []byte, i int, pattern tokenPattern) int {
	prefix := pattern.prefix
	if i+len(prefix) > len(data) {
		return -1
	}

	// Check if the prefix matches at this position.
	for k := range prefix {
		if data[i+k] != prefix[k] {
			return -1
		}
	}

	// Extract the token body (alphanumeric, underscore, hyphen).
	end := i + len(prefix)
	for end < len(data) && isTokenByte(data[end]) {
		end++
	}

	tokenLen := end - i - len(prefix)
	if tokenLen < pattern.minBodyLen {
		return -1
	}
	return end
}

// tokenPattern describes a known payment token prefix and its minimum body length.
type tokenPattern struct {
	prefix     string
	minBodyLen int // minimum number of characters after the prefix
}

// tokenPatterns lists all recognized payment token patterns.
// Longer prefixes are listed first so they match before shorter ones
// (e.g., "sk_live_" before a hypothetical shorter prefix).
func tokenPatterns() []tokenPattern {
	return []tokenPattern{
		// Stripe tokens (longer prefixes first).
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "sk_live_", minBodyLen: 16},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "pk_live_", minBodyLen: 16},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "sk_test_", minBodyLen: 16},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "pk_test_", minBodyLen: 16},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "price_", minBodyLen: 8},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "prod_", minBodyLen: 8},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "tok_", minBodyLen: 8},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "cus_", minBodyLen: 8},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "sub_", minBodyLen: 8},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "pi_", minBodyLen: 8},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "pm_", minBodyLen: 8},

		// PayPal tokens.
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "PAYID-", minBodyLen: 16},

		// Square tokens.
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "sq0idp-", minBodyLen: 16},
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		{prefix: "sq0csp-", minBodyLen: 16},
	}
}
