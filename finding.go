package embargo

// Kind identifies a built-in or application-defined detection family.
type Kind string

// Finding locates sensitive data in the original input without retaining its value.
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
	// KindPAN selects pan detection.
	KindPAN Kind = "pan"
	// KindEmail selects email detection.
	KindEmail Kind = "email"
	// KindJPPhone selects phone_jp detection.
	KindJPPhone Kind = "phone_jp"
	// KindMyNumber selects mynumber detection.
	KindMyNumber Kind = "mynumber"
	// KindJWT selects jwt detection.
	KindJWT Kind = "jwt"
	// KindAWSKey selects awskey detection.
	KindAWSKey Kind = "awskey"
	// KindIBAN selects iban detection.
	KindIBAN Kind = "iban"
	// KindIPAddr selects ipaddr detection.
	KindIPAddr Kind = "ipaddr"
	// KindSWIFTBIC selects swiftbic detection.
	KindSWIFTBIC Kind = "swiftbic"
	// KindABARouting selects aba_routing detection.
	KindABARouting Kind = "aba_routing"
	// KindUKSortCode selects uk_sortcode detection.
	KindUKSortCode Kind = "uk_sortcode"
	// KindCVV selects cvv detection.
	KindCVV Kind = "cvv"
	// KindCardExpiry selects card_expiry detection.
	KindCardExpiry Kind = "card_expiry"
	// KindPaymentToken selects payment_token detection.
	KindPaymentToken Kind = "payment_token"
	// KindBankAccount selects bank_account detection.
	KindBankAccount Kind = "bank_account"
	// KindACHTrace selects ach_trace detection.
	KindACHTrace Kind = "ach_trace"
	// KindMerchantID selects merchant_id detection.
	KindMerchantID Kind = "merchant_id"
	// KindBTC selects btc detection.
	KindBTC Kind = "btc"
	// KindETH selects eth detection.
	KindETH Kind = "eth"
	// KindGitHubToken selects github_token detection.
	KindGitHubToken Kind = "github_token"
	// KindSlackToken selects slack_token detection.
	KindSlackToken Kind = "slack_token"
	// KindGoogleAPIKey selects google_api_key detection.
	KindGoogleAPIKey Kind = "google_api_key"
	// KindPrivateKeyPEM selects private_key_pem detection.
	KindPrivateKeyPEM Kind = "private_key_pem"
)
