package detect

// DetectorName identifies a detector; built-ins use Name* constants and custom detectors may choose their own names.
type DetectorName string

// Detector name constants identify the source of a finding.
const (
	// NameCredential identifies secret values in rendered assignments and URLs.
	NameCredential DetectorName = "credential"
	// NamePAN is the detector name for credit card numbers (Primary Account Numbers).
	NamePAN DetectorName = "pan"
	// NameEmail is the detector name for email addresses.
	NameEmail DetectorName = "email"
	// NameJPPhone is the detector name for Japanese phone numbers.
	NameJPPhone DetectorName = "phone_jp"
	// NameMyNumber is the detector name for Japanese My Number (individual number).
	NameMyNumber DetectorName = "mynumber"
	// NameJWT is the detector name for JSON Web Tokens.
	NameJWT DetectorName = "jwt"
	// NameAWSKey is the detector name for AWS Access Key IDs.
	NameAWSKey DetectorName = "awskey"
	// NameIBAN is the detector name for International Bank Account Numbers.
	NameIBAN DetectorName = "iban"
	// NameIPAddr is the detector name for IP addresses.
	NameIPAddr DetectorName = "ipaddr"
	// NameSWIFTBIC is the detector name for SWIFT/BIC codes.
	NameSWIFTBIC DetectorName = "swiftbic"
	// NameABARouting is the detector name for US ABA routing transit numbers.
	NameABARouting DetectorName = "aba_routing"
	// NameUKSortCode is the detector name for UK bank sort codes.
	NameUKSortCode DetectorName = "uk_sortcode"
	// NameCVV is the detector name for card verification values (CVV/CVC).
	NameCVV DetectorName = "cvv"
	// NameCardExpiry is the detector name for payment card expiration dates.
	NameCardExpiry DetectorName = "card_expiry"
	// NamePaymentToken is the detector name for payment processor tokens.
	NamePaymentToken DetectorName = "payment_token"
	// NameBankAccount is the detector name for bank account numbers (context-based).
	NameBankAccount DetectorName = "bank_account"
	// NameACHTrace is the detector name for ACH trace numbers.
	NameACHTrace DetectorName = "ach_trace"
	// NameMerchantID is the detector name for merchant and terminal IDs.
	NameMerchantID DetectorName = "merchant_id"
	// NameBTC is the detector name for Bitcoin addresses.
	NameBTC DetectorName = "btc"
	// NameETH is the detector name for Ethereum addresses.
	NameETH DetectorName = "eth"
	// NameGitHubToken is the detector name for GitHub access tokens.
	NameGitHubToken DetectorName = "github_token"
	// NameSlackToken is the detector name for Slack API tokens.
	NameSlackToken DetectorName = "slack_token"
	// NameGoogleAPIKey is the detector name for Google API keys.
	NameGoogleAPIKey DetectorName = "google_api_key"
	// NamePrivateKeyPEM is the detector name for PEM-encoded private key headers.
	NamePrivateKeyPEM DetectorName = "private_key_pem"
)

// Detector extracts findings from bytes without modifying the input. Implementations used by concurrent scanner calls must support concurrent use.
type Detector interface {
	// Name returns the detector identifier used in its findings; scanner registrations with the same name replace earlier ones.
	Name() DetectorName

	// Hints returns exhaustive pre-filter substrings: every possible match must contain at least one, or scanning may miss it. ASCII letters are matched case-insensitively; other bytes match exactly. Nil or empty hints always run Scan; keep hints unchanged after registration.
	Hints() [][]byte

	// Scan returns findings with original byte offsets. It must handle arbitrary input, including calls without hint filtering; use dedicated parsers and domain validation where practical.
	Scan(data []byte) []Finding
}

// Finding describes a match in the original input using a half-open byte range [Start:End), not rune indexes.
type Finding struct {
	// DetectorName identifies the detector that produced the match.
	DetectorName DetectorName
	// Start is the inclusive byte offset in the original input.
	Start int
	// End is the exclusive byte offset in the original input.
	End int
	// Confidence is a score in [0, 1], using detector-specific scoring rules.
	Confidence float64
}

// ensure that all detectors implement the Detector interface.
var (
	_ Detector = (*PAN)(nil)
	_ Detector = (*Email)(nil)
	_ Detector = (*JPPhone)(nil)
	_ Detector = (*MyNumber)(nil)
	_ Detector = (*JWT)(nil)
	_ Detector = (*AWSKey)(nil)
	_ Detector = (*IBAN)(nil)
	_ Detector = (*IPAddr)(nil)
	_ Detector = (*SWIFTBIC)(nil)
	_ Detector = (*ABARouting)(nil)
	_ Detector = (*UKSortCode)(nil)
	_ Detector = (*CVV)(nil)
	_ Detector = (*CardExpiry)(nil)
	_ Detector = (*PaymentToken)(nil)
	_ Detector = (*BankAccount)(nil)
	_ Detector = (*ACHTrace)(nil)
	_ Detector = (*MerchantID)(nil)
	_ Detector = (*BTC)(nil)
	_ Detector = (*ETH)(nil)
	_ Detector = (*GitHubToken)(nil)
	_ Detector = (*SlackToken)(nil)
	_ Detector = (*GoogleAPIKey)(nil)
	_ Detector = (*PrivateKeyPEM)(nil)
)
