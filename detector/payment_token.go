package detector

// PaymentTokenDetail holds payment processor token-specific detail information.
type PaymentTokenDetail struct {
	// Provider is the payment processor name (e.g., "Stripe", "PayPal", "Square").
	Provider string
	// TokenType describes the type of token (e.g., "secret_key", "publishable_key",
	// "token", "payment_intent", "customer", "subscription").
	TokenType string
}

// PaymentToken detects payment processor API tokens and keys in text.
//
// Payment processor tokens are identifiers used by services such as Stripe,
// PayPal, and Square. These tokens have distinctive prefixes that make them
// highly identifiable.
//
// Supported token patterns:
//   - Stripe: sk_live_, pk_live_, sk_test_, pk_test_, tok_, pi_, pm_, cus_, sub_, price_, prod_
//   - PayPal: PAYID-
//   - Square: sq0idp-, sq0csp-
//
// Detection logic:
//  1. Scan for known token prefixes
//  2. Validate that the prefix is followed by a sufficient number of
//     alphanumeric characters (or base62 characters including underscores)
//  3. Check word boundaries to avoid false matches
//
// Confidence: 0.9 when a recognized prefix and valid token body are found.
type PaymentToken struct{}

// NewPaymentToken creates a new payment processor token detector.
func NewPaymentToken() *PaymentToken {
	return &PaymentToken{}
}

// Name returns "payment_token".
func (d *PaymentToken) Name() DetectorName {
	return NamePaymentToken
}

// Hints returns byte sequences for pre-filtering.
// Each token type has a distinctive prefix, providing excellent pre-filtering.
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

// Scan examines data for payment processor tokens and returns findings.
func (d *PaymentToken) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data); i++ {
		// Word boundary: preceding character must not be alphanumeric or underscore.
		if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '_') {
			continue
		}

		for _, pattern := range tokenPatterns {
			prefix := pattern.prefix
			if i+len(prefix) > len(data) {
				continue
			}

			// Check if the prefix matches at this position.
			match := true
			for k := range prefix {
				if data[i+k] != prefix[k] {
					match = false
					break
				}
			}
			if !match {
				continue
			}

			// Extract the token body (alphanumeric, underscore, hyphen).
			end := i + len(prefix)
			for end < len(data) && isTokenChar(data[end]) {
				end++
			}

			tokenLen := end - i - len(prefix)
			if tokenLen < pattern.minBodyLen {
				continue
			}

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        i,
				End:          end,
				Confidence:   0.9,
				RawValue:     string(data[i:end]),
				Detail: &PaymentTokenDetail{
					Provider:  pattern.provider,
					TokenType: pattern.tokenType,
				},
			})

			i = end - 1
			break // Move to next position after matching.
		}
	}

	return findings
}

// isTokenChar reports whether b is a valid character in a payment token body
// (alphanumeric, underscore, or hyphen).
func isTokenChar(b byte) bool {
	return isAlphaNum(b) || b == '_' || b == '-'
}

// tokenPattern describes a known payment token prefix and its metadata.
type tokenPattern struct {
	prefix     string
	provider   string
	tokenType  string
	minBodyLen int // minimum number of characters after the prefix
}

// tokenPatterns lists all recognized payment token patterns.
// Longer prefixes are listed first so they match before shorter ones
// (e.g., "sk_live_" before a hypothetical shorter prefix).
var tokenPatterns = []tokenPattern{
	// Stripe tokens (longer prefixes first).
	{prefix: "sk_live_", provider: "Stripe", tokenType: "secret_key", minBodyLen: 16},
	{prefix: "pk_live_", provider: "Stripe", tokenType: "publishable_key", minBodyLen: 16},
	{prefix: "sk_test_", provider: "Stripe", tokenType: "secret_key_test", minBodyLen: 16},
	{prefix: "pk_test_", provider: "Stripe", tokenType: "publishable_key_test", minBodyLen: 16},
	{prefix: "price_", provider: "Stripe", tokenType: "price", minBodyLen: 8},
	{prefix: "prod_", provider: "Stripe", tokenType: "product", minBodyLen: 8},
	{prefix: "tok_", provider: "Stripe", tokenType: "token", minBodyLen: 8},
	{prefix: "cus_", provider: "Stripe", tokenType: "customer", minBodyLen: 8},
	{prefix: "sub_", provider: "Stripe", tokenType: "subscription", minBodyLen: 8},
	{prefix: "pi_", provider: "Stripe", tokenType: "payment_intent", minBodyLen: 8},
	{prefix: "pm_", provider: "Stripe", tokenType: "payment_method", minBodyLen: 8},

	// PayPal tokens.
	{prefix: "PAYID-", provider: "PayPal", tokenType: "payment_id", minBodyLen: 16},

	// Square tokens.
	{prefix: "sq0idp-", provider: "Square", tokenType: "application_id", minBodyLen: 16},
	{prefix: "sq0csp-", provider: "Square", tokenType: "application_secret", minBodyLen: 16},
}
