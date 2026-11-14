package detector

// PaymentTokenDetail holds payment processor token-specific detail information.
type PaymentTokenDetail struct {
	// Provider is the payment processor name (e.g., "Stripe", "PayPal", "Square").
	Provider string
	// TokenType describes the type of token (e.g., "secret_key", "publishable_key",
	// "token", "payment_intent", "customer", "subscription").
	TokenType string
}

// PaymentToken detects Stripe, PayPal, and Square identifiers by prefix and body shape.
//
//  1. Find Stripe sk_live_, pk_live_, sk_test_, pk_test_, tok_, pi_, pm_, cus_, sub_, price_, or prod_; PayPal PAYID-; or Square sq0idp- or sq0csp- at a leading word boundary.
//  2. Consume ASCII alphanumerics, underscores, or hyphens; require at least 16 body characters for keys, PayPal, and Square, or eight for the remaining Stripe identifiers.
//  3. Score a match as 0.9 and record the provider and token type; no service authentication is attempted.
type PaymentToken struct{}

// NewPaymentToken creates a new payment processor token detector.
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

	for i := 0; i < len(data); i++ {
		// Word boundary: preceding character must not be alphanumeric or underscore.
		if i > 0 && (isAlphaNum(data[i-1]) || data[i-1] == '_') && !encodedSeparatorBefore(data, i) {
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

// Payment processor names. Each is written once rather than on every row of
// tokenPatterns below: a provider issues many prefixes, so the name repeats as
// often as the provider has token kinds.
const (
	providerStripe = "Stripe"
	providerPayPal = "PayPal"
	providerSquare = "Square"
)

// tokenPatterns lists all recognized payment token patterns.
// Longer prefixes are listed first so they match before shorter ones
// (e.g., "sk_live_" before a hypothetical shorter prefix).
var tokenPatterns = []tokenPattern{
	// Stripe tokens (longer prefixes first).
	{prefix: "sk_live_", provider: providerStripe, tokenType: "secret_key", minBodyLen: 16},
	{prefix: "pk_live_", provider: providerStripe, tokenType: "publishable_key", minBodyLen: 16},
	{prefix: "sk_test_", provider: providerStripe, tokenType: "secret_key_test", minBodyLen: 16},
	{prefix: "pk_test_", provider: providerStripe, tokenType: "publishable_key_test", minBodyLen: 16},
	{prefix: "price_", provider: providerStripe, tokenType: "price", minBodyLen: 8},
	{prefix: "prod_", provider: providerStripe, tokenType: "product", minBodyLen: 8},
	{prefix: "tok_", provider: providerStripe, tokenType: "token", minBodyLen: 8},
	{prefix: "cus_", provider: providerStripe, tokenType: "customer", minBodyLen: 8},
	{prefix: "sub_", provider: providerStripe, tokenType: "subscription", minBodyLen: 8},
	{prefix: "pi_", provider: providerStripe, tokenType: "payment_intent", minBodyLen: 8},
	{prefix: "pm_", provider: providerStripe, tokenType: "payment_method", minBodyLen: 8},

	// PayPal tokens.
	{prefix: "PAYID-", provider: providerPayPal, tokenType: "payment_id", minBodyLen: 16},

	// Square tokens.
	{prefix: "sq0idp-", provider: providerSquare, tokenType: "application_id", minBodyLen: 16},
	{prefix: "sq0csp-", provider: providerSquare, tokenType: "application_secret", minBodyLen: 16},
}
