package detector

// DetectorName identifies a detector; built-ins use Name* constants and custom detectors may choose their own names.
//
// revive:disable-next-line:exported
type DetectorName string

// Detector name constants. Use these with [Finding.Is] or for comparison
// with [Finding.DetectorName] to identify the source of a finding.
const (
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

// SensitiveKind classifies findings as financial data, PII, or credentials; see [Finding.Kind].
type SensitiveKind string

const (
	// KindFinancial identifies financial data, including bank, payment card, and cryptocurrency identifiers.
	KindFinancial SensitiveKind = "financial"
	// KindPII identifies personal data: email, phone, My Number, and IP addresses.
	KindPII SensitiveKind = "pii"
	// KindCredential identifies authentication credentials, tokens, and private key headers.
	KindCredential SensitiveKind = "credential"
)

// kindMapping maps each built-in detector name to its semantic kind.
// Custom detectors not in this map return "" (empty SensitiveKind) from Kind().
var kindMapping = map[DetectorName]SensitiveKind{
	NamePAN:           KindFinancial,
	NameIBAN:          KindFinancial,
	NameABARouting:    KindFinancial,
	NameUKSortCode:    KindFinancial,
	NameCVV:           KindFinancial,
	NameCardExpiry:    KindFinancial,
	NameBankAccount:   KindFinancial,
	NameACHTrace:      KindFinancial,
	NameMerchantID:    KindFinancial,
	NameSWIFTBIC:      KindFinancial,
	NameBTC:           KindFinancial,
	NameETH:           KindFinancial,
	NameEmail:         KindPII,
	NameJPPhone:       KindPII,
	NameMyNumber:      KindPII,
	NameIPAddr:        KindPII,
	NameJWT:           KindCredential,
	NameAWSKey:        KindCredential,
	NamePaymentToken:  KindCredential,
	NameGitHubToken:   KindCredential,
	NameSlackToken:    KindCredential,
	NameGoogleAPIKey:  KindCredential,
	NamePrivateKeyPEM: KindCredential,
}

// ConfidenceLevel represents a human-readable confidence threshold.
// Use [Finding.Level] to obtain this from a finding.
type ConfidenceLevel int

const (
	// ConfidenceLow means Confidence < 0.4.
	ConfidenceLow ConfidenceLevel = iota
	// ConfidenceMedium means 0.4 <= Confidence < 0.8.
	ConfidenceMedium
	// ConfidenceHigh means Confidence >= 0.8.
	ConfidenceHigh
)

// String returns "low", "medium", or "high", or "unknown" for an undefined level.
func (cl ConfidenceLevel) String() string {
	switch cl {
	case ConfidenceLow:
		return "low"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	default:
		return "unknown"
	}
}

// Detector extracts findings from bytes without modifying the input. Implementations used by concurrent scanner calls must support concurrent use.
type Detector interface {
	// Name returns the detector identifier used in its findings; scanner registrations with the same name replace earlier ones.
	Name() DetectorName

	// Hints returns exhaustive pre-filter substrings: every possible match must contain at least one, or scanning may miss it. ASCII letters are matched case-insensitively; other bytes match exactly. Nil or empty hints always run Scan; keep hints unchanged after registration.
	Hints() [][]byte

	// Scan returns findings with original byte offsets and RawValue equal to data[Start:End]. It must handle arbitrary input, including calls without hint filtering; use dedicated parsers and domain validation where practical.
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

	// Confidence is the detector-specific score in [0, 1]; each detector documents its scoring rules.
	Confidence float64

	// RawValue is the exact string that was matched in the input text.
	RawValue string

	// Detail holds optional detector-specific metadata, such as *PANDetail. Use the typed accessor methods to check its concrete type.
	Detail any
}

// Is reports whether the detector name matches detectorName; built-in names use Name* constants.
func (f Finding) Is(detectorName DetectorName) bool {
	return f.DetectorName == detectorName
}

// IsPAN reports whether this finding is a credit card number (PAN).
func (f Finding) IsPAN() bool { return f.DetectorName == NamePAN }

// IsEmail reports whether this finding is an email address.
func (f Finding) IsEmail() bool { return f.DetectorName == NameEmail }

// IsJPPhone reports whether this finding is a Japanese phone number.
func (f Finding) IsJPPhone() bool { return f.DetectorName == NameJPPhone }

// IsMyNumber reports whether this finding is a Japanese My Number.
func (f Finding) IsMyNumber() bool { return f.DetectorName == NameMyNumber }

// IsJWT reports whether this finding is a JSON Web Token.
func (f Finding) IsJWT() bool { return f.DetectorName == NameJWT }

// IsAWSKey reports whether this finding is an AWS Access Key ID.
func (f Finding) IsAWSKey() bool { return f.DetectorName == NameAWSKey }

// IsIBAN reports whether this finding is an International Bank Account Number.
func (f Finding) IsIBAN() bool { return f.DetectorName == NameIBAN }

// IsIPAddr reports whether this finding is an IP address.
func (f Finding) IsIPAddr() bool { return f.DetectorName == NameIPAddr }

// IsSWIFTBIC reports whether this finding is a SWIFT/BIC code.
func (f Finding) IsSWIFTBIC() bool { return f.DetectorName == NameSWIFTBIC }

// IsABARouting reports whether this finding is a US ABA routing number.
func (f Finding) IsABARouting() bool { return f.DetectorName == NameABARouting }

// IsUKSortCode reports whether this finding is a UK sort code.
func (f Finding) IsUKSortCode() bool { return f.DetectorName == NameUKSortCode }

// IsCVV reports whether this finding is a CVV/CVC code.
func (f Finding) IsCVV() bool { return f.DetectorName == NameCVV }

// IsCardExpiry reports whether this finding is a card expiration date.
func (f Finding) IsCardExpiry() bool { return f.DetectorName == NameCardExpiry }

// IsPaymentToken reports whether this finding is a payment processor token.
func (f Finding) IsPaymentToken() bool { return f.DetectorName == NamePaymentToken }

// IsBankAccount reports whether this finding is a bank account number (context-based).
func (f Finding) IsBankAccount() bool { return f.DetectorName == NameBankAccount }

// IsACHTrace reports whether this finding is an ACH trace number.
func (f Finding) IsACHTrace() bool { return f.DetectorName == NameACHTrace }

// IsMerchantID reports whether this finding is a merchant or terminal ID.
func (f Finding) IsMerchantID() bool { return f.DetectorName == NameMerchantID }

// IsBTC reports whether this finding is a Bitcoin address.
func (f Finding) IsBTC() bool { return f.DetectorName == NameBTC }

// IsETH reports whether this finding is an Ethereum address.
func (f Finding) IsETH() bool { return f.DetectorName == NameETH }

// IsGitHubToken reports whether this finding is a GitHub access token.
func (f Finding) IsGitHubToken() bool { return f.DetectorName == NameGitHubToken }

// IsSlackToken reports whether this finding is a Slack API token.
func (f Finding) IsSlackToken() bool { return f.DetectorName == NameSlackToken }

// IsGoogleAPIKey reports whether this finding is a Google API key.
func (f Finding) IsGoogleAPIKey() bool { return f.DetectorName == NameGoogleAPIKey }

// IsPrivateKeyPEM reports whether this finding is a PEM private key header.
func (f Finding) IsPrivateKeyPEM() bool { return f.DetectorName == NamePrivateKeyPEM }

// PANDetail asserts Detail to *PANDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) PANDetail() (*PANDetail, bool) {
	d, ok := f.Detail.(*PANDetail)
	return d, ok
}

// EmailDetail asserts Detail to *EmailDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) EmailDetail() (*EmailDetail, bool) {
	d, ok := f.Detail.(*EmailDetail)
	return d, ok
}

// JPPhoneDetail asserts Detail to *JPPhoneDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) JPPhoneDetail() (*JPPhoneDetail, bool) {
	d, ok := f.Detail.(*JPPhoneDetail)
	return d, ok
}

// JWTDetail asserts Detail to *JWTDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) JWTDetail() (*JWTDetail, bool) {
	d, ok := f.Detail.(*JWTDetail)
	return d, ok
}

// AWSKeyDetail asserts Detail to *AWSKeyDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) AWSKeyDetail() (*AWSKeyDetail, bool) {
	d, ok := f.Detail.(*AWSKeyDetail)
	return d, ok
}

// IBANDetail asserts Detail to *IBANDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) IBANDetail() (*IBANDetail, bool) {
	d, ok := f.Detail.(*IBANDetail)
	return d, ok
}

// IPAddrDetail asserts Detail to *IPAddrDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) IPAddrDetail() (*IPAddrDetail, bool) {
	d, ok := f.Detail.(*IPAddrDetail)
	return d, ok
}

// MyNumberDetail asserts Detail to *MyNumberDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) MyNumberDetail() (*MyNumberDetail, bool) {
	d, ok := f.Detail.(*MyNumberDetail)
	return d, ok
}

// SWIFTBICDetail asserts Detail to *SWIFTBICDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) SWIFTBICDetail() (*SWIFTBICDetail, bool) {
	d, ok := f.Detail.(*SWIFTBICDetail)
	return d, ok
}

// ABARoutingDetail asserts Detail to *ABARoutingDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) ABARoutingDetail() (*ABARoutingDetail, bool) {
	d, ok := f.Detail.(*ABARoutingDetail)
	return d, ok
}

// UKSortCodeDetail asserts Detail to *UKSortCodeDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) UKSortCodeDetail() (*UKSortCodeDetail, bool) {
	d, ok := f.Detail.(*UKSortCodeDetail)
	return d, ok
}

// CVVDetail asserts Detail to *CVVDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) CVVDetail() (*CVVDetail, bool) {
	d, ok := f.Detail.(*CVVDetail)
	return d, ok
}

// CardExpiryDetail asserts Detail to *CardExpiryDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) CardExpiryDetail() (*CardExpiryDetail, bool) {
	d, ok := f.Detail.(*CardExpiryDetail)
	return d, ok
}

// PaymentTokenDetail asserts Detail to *PaymentTokenDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) PaymentTokenDetail() (*PaymentTokenDetail, bool) {
	d, ok := f.Detail.(*PaymentTokenDetail)
	return d, ok
}

// BankAccountDetail asserts Detail to *BankAccountDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) BankAccountDetail() (*BankAccountDetail, bool) {
	d, ok := f.Detail.(*BankAccountDetail)
	return d, ok
}

// ACHTraceDetail asserts Detail to *ACHTraceDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) ACHTraceDetail() (*ACHTraceDetail, bool) {
	d, ok := f.Detail.(*ACHTraceDetail)
	return d, ok
}

// MerchantIDDetail asserts Detail to *MerchantIDDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) MerchantIDDetail() (*MerchantIDDetail, bool) {
	d, ok := f.Detail.(*MerchantIDDetail)
	return d, ok
}

// BTCDetail asserts Detail to *BTCDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) BTCDetail() (*BTCDetail, bool) {
	d, ok := f.Detail.(*BTCDetail)
	return d, ok
}

// ETHDetail asserts Detail to *ETHDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) ETHDetail() (*ETHDetail, bool) {
	d, ok := f.Detail.(*ETHDetail)
	return d, ok
}

// GitHubTokenDetail asserts Detail to *GitHubTokenDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) GitHubTokenDetail() (*GitHubTokenDetail, bool) {
	d, ok := f.Detail.(*GitHubTokenDetail)
	return d, ok
}

// SlackTokenDetail asserts Detail to *SlackTokenDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) SlackTokenDetail() (*SlackTokenDetail, bool) {
	d, ok := f.Detail.(*SlackTokenDetail)
	return d, ok
}

// GoogleAPIKeyDetail asserts Detail to *GoogleAPIKeyDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) GoogleAPIKeyDetail() (*GoogleAPIKeyDetail, bool) {
	d, ok := f.Detail.(*GoogleAPIKeyDetail)
	return d, ok
}

// PrivateKeyPEMDetail asserts Detail to *PrivateKeyPEMDetail, returning (nil, false) on a type mismatch. A typed nil pointer returns (nil, true).
func (f Finding) PrivateKeyPEMDetail() (*PrivateKeyPEMDetail, bool) {
	d, ok := f.Detail.(*PrivateKeyPEMDetail)
	return d, ok
}

// Level classifies Confidence using [ConfidenceLow], [ConfidenceMedium], and [ConfidenceHigh].
func (f Finding) Level() ConfidenceLevel {
	switch {
	case f.Confidence >= 0.8:
		return ConfidenceHigh
	case f.Confidence >= 0.4:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// Kind returns the built-in category for DetectorName, or an empty string for an unrecognized name.
func (f Finding) Kind() SensitiveKind {
	return kindMapping[f.DetectorName]
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
	_ Detector = (*Regex)(nil)
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
