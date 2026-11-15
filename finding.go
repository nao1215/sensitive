package embargo

// Kind identifies a built-in or application-defined detection family.
type Kind string

// Finding locates a sensitive-data candidate in the original input without retaining its value.
type Finding struct {
	// Kind identifies the detection family.
	Kind Kind
	// Start is the inclusive byte offset.
	Start int
	// End is the exclusive byte offset.
	End int
	// Confidence is a heuristic score in [0,1], not a probability.
	Confidence float64
}

const (
	// KindServiceToken selects documented service prefixes and Slack webhook secrets.
	KindServiceToken Kind = "service_token"
	// KindHighEntropy selects unlabeled random-looking tokens at confidence 0.3.
	KindHighEntropy Kind = "high_entropy"
	// KindCredential selects secret assignments, Authorization values and URL/DSN passwords.
	KindCredential Kind = "credential"
	// KindPAN selects payment card candidates, including lower-confidence checksum failures.
	KindPAN Kind = "pan"
	// KindEmail selects email addresses.
	KindEmail Kind = "email"
	// KindJPPhone selects Japanese telephone numbers.
	KindJPPhone Kind = "phone_jp"
	// KindMyNumber selects Japanese My Number identifiers.
	KindMyNumber Kind = "mynumber"
	// KindJWT selects JSON Web Token candidates.
	KindJWT Kind = "jwt"
	// KindAWSKey selects AWS access key IDs.
	KindAWSKey Kind = "awskey"
	// KindIBAN selects international bank account numbers.
	KindIBAN Kind = "iban"
	// KindIPAddr selects IPv4 and IPv6 addresses.
	KindIPAddr Kind = "ipaddr"
	// KindSWIFTBIC selects SWIFT/BIC candidates.
	KindSWIFTBIC Kind = "swiftbic"
	// KindABARouting selects US ABA routing numbers.
	KindABARouting Kind = "aba_routing"
	// KindUKSortCode selects UK bank sort codes.
	KindUKSortCode Kind = "uk_sortcode"
	// KindCVV selects card verification codes near context keywords.
	KindCVV Kind = "cvv"
	// KindCardExpiry selects card expiry dates near context keywords.
	KindCardExpiry Kind = "card_expiry"
	// KindPaymentToken selects payment-provider token candidates.
	KindPaymentToken Kind = "payment_token"
	// KindBankAccount selects bank account numbers near context keywords.
	KindBankAccount Kind = "bank_account"
	// KindACHTrace selects ACH trace numbers near context keywords.
	KindACHTrace Kind = "ach_trace"
	// KindMerchantID selects merchant IDs near context keywords.
	KindMerchantID Kind = "merchant_id"
	// KindBTC selects Bitcoin addresses.
	KindBTC Kind = "btc"
	// KindETH selects Ethereum addresses.
	KindETH Kind = "eth"
	// KindGitHubToken selects GitHub token candidates.
	KindGitHubToken Kind = "github_token"
	// KindSlackToken selects Slack token candidates.
	KindSlackToken Kind = "slack_token"
	// KindGoogleAPIKey selects Google API key candidates.
	KindGoogleAPIKey Kind = "google_api_key"
	// KindPrivateKeyPEM selects PEM private keys through their END marker, or incomplete headers.
	KindPrivateKeyPEM Kind = "private_key_pem"
)
