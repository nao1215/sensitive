package detector

// DetectorName is the type-safe identifier for a detector.
// Built-in detectors use the Name* constants defined below.
// User-defined detectors (e.g., [Regex]) can use any value.
//
//revive:disable-next-line:exported
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
)

// SensitiveKind categorizes a finding into a broad semantic group for
// downstream classification, auditing, and statistics. Use [Finding.Kind]
// to obtain the kind from a finding.
//
//	switch f.Kind() {
//	case detector.KindFinancial:
//	    // PAN, IBAN, ABA routing, sort code, etc.
//	case detector.KindPII:
//	    // email, phone, My Number, IP address
//	case detector.KindCredential:
//	    // JWT, AWS key, payment token
//	}
type SensitiveKind string

const (
	// KindFinancial indicates financial instrument data (PAN, IBAN, ABA routing,
	// sort code, CVV, card expiry, bank account, ACH trace, merchant ID, SWIFT/BIC).
	KindFinancial SensitiveKind = "financial"
	// KindPII indicates personally identifiable information
	// (email, phone number, My Number, IP address).
	KindPII SensitiveKind = "pii"
	// KindCredential indicates authentication credentials or tokens
	// (JWT, AWS access key, payment processor token).
	KindCredential SensitiveKind = "credential"
)

// kindMapping maps each built-in detector name to its semantic kind.
// Custom detectors not in this map return "" (empty SensitiveKind) from Kind().
var kindMapping = map[DetectorName]SensitiveKind{
	NamePAN:          KindFinancial,
	NameIBAN:         KindFinancial,
	NameABARouting:   KindFinancial,
	NameUKSortCode:   KindFinancial,
	NameCVV:          KindFinancial,
	NameCardExpiry:   KindFinancial,
	NameBankAccount:  KindFinancial,
	NameACHTrace:     KindFinancial,
	NameMerchantID:   KindFinancial,
	NameSWIFTBIC:     KindFinancial,
	NameEmail:        KindPII,
	NameJPPhone:      KindPII,
	NameMyNumber:     KindPII,
	NameIPAddr:       KindPII,
	NameJWT:          KindCredential,
	NameAWSKey:       KindCredential,
	NamePaymentToken: KindCredential,
}

// ConfidenceLevel represents a human-readable confidence threshold.
// Use [Finding.Level] to obtain this from a finding.
type ConfidenceLevel int

const (
	// ConfidenceLow indicates weak confidence (Confidence < 0.4).
	// The detected value may be a false positive and should be treated with caution.
	ConfidenceLow ConfidenceLevel = iota
	// ConfidenceMedium indicates moderate confidence (0.4 <= Confidence < 0.8).
	// The detected value is likely genuine but has not passed all validation stages.
	ConfidenceMedium
	// ConfidenceHigh indicates strong confidence (Confidence >= 0.8).
	// The detected value has passed multiple validation stages (e.g., BIN + Luhn for PAN).
	ConfidenceHigh
)

// String returns the human-readable name of the confidence level.
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

// Detector is the interface that each sensitive data detector must implement.
// Each data type (PAN, email, phone, etc.) has its own dedicated implementation.
//
// Detectors are designed to work within the Scanner's multi-stage filtering
// pipeline. The Hints method enables fast pre-filtering, and Scan is only
// called on data that passes the hint check.
type Detector interface {
	// Name returns the identifier of this detector (e.g., NamePAN, NameEmail).
	// This value is used in Finding.DetectorName to identify which detector
	// produced a given finding.
	Name() DetectorName

	// Hints returns byte sequences used for fast pre-filtering.
	// The Scanner uses bytes.Contains to check each hint against the input.
	// If none of the hints match, Scan is not called for this detector,
	// allowing the vast majority of non-matching input to be skipped quickly.
	//
	// IMPORTANT: Hints must be exhaustive for the detector's domain — every
	// possible match must contain at least one of the returned byte sequences.
	// Non-exhaustive hints will cause silent detection misses. For example,
	// an IBAN detector must include ALL supported country codes as hints,
	// not just a frequently-used subset.
	//
	// Returning nil or an empty slice causes Scan to be called unconditionally,
	// which is safe but discouraged for performance reasons.
	Hints() [][]byte

	// Scan examines the given byte slice and returns all findings.
	// It is only called on data that has passed the hint-based pre-filter.
	// Implementations should use dedicated parsers and domain rule validation
	// rather than relying solely on regular expressions.
	Scan(data []byte) []Finding
}

// Finding represents a single instance of detected sensitive data within
// the scanned text. It contains the detector name, byte-level position,
// confidence score, the raw matched value, and optional detector-specific
// detail information.
type Finding struct {
	// DetectorName is the identifier of the detector that produced this
	// finding (e.g., NamePAN, NameEmail, NameJPPhone, NameMyNumber).
	DetectorName DetectorName

	// Start is the starting byte offset (inclusive) of the detected value
	// within the original input.
	Start int

	// End is the ending byte offset (exclusive) of the detected value
	// within the original input.
	End int

	// Confidence is a value between 0.0 and 1.0 indicating how likely
	// the detected value is genuine sensitive data. Higher values indicate
	// stronger confidence. For example, a PAN that passes both BIN prefix
	// and Luhn checks will have higher confidence than one that only
	// matches the digit pattern.
	Confidence float64

	// RawValue is the exact string that was matched in the input text.
	RawValue string

	// Detail holds detector-specific information about the finding.
	// The concrete type depends on the detector (e.g., *PANDetail
	// for PAN findings). It may be nil if the detector does not provide
	// additional detail.
	//
	// Design note: Detail is typed as any rather than a generic type parameter
	// because Scanner.Scan returns []Finding from multiple detectors, each
	// producing a different Detail type. A generic Finding[T] would make
	// heterogeneous slices impossible. Use the typed accessor methods
	// (e.g., PANDetail, EmailDetail) which return (T, bool) for safe,
	// panic-free access without direct type assertions.
	Detail any
}

// Is reports whether this finding was produced by the detector with the given name.
// Use the Name* constants for type-safe comparison:
//
//	if f.Is(detector.NamePAN) { ... }
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

// PANDetail returns the PAN-specific detail if this finding was produced by
// the PAN detector. The second return value indicates whether the assertion
// succeeded. When the finding is not a PAN or Detail is nil, it returns (nil, false).
//
//	if detail, ok := f.PANDetail(); ok {
//	    fmt.Println(detail.Brand, detail.Last4)
//	}
func (f Finding) PANDetail() (*PANDetail, bool) {
	d, ok := f.Detail.(*PANDetail)
	return d, ok
}

// EmailDetail returns the email-specific detail if this finding was produced by
// the Email detector. Returns (nil, false) when not applicable.
func (f Finding) EmailDetail() (*EmailDetail, bool) {
	d, ok := f.Detail.(*EmailDetail)
	return d, ok
}

// JPPhoneDetail returns the Japanese phone number-specific detail if this finding
// was produced by the JPPhone detector. Returns (nil, false) when not applicable.
func (f Finding) JPPhoneDetail() (*JPPhoneDetail, bool) {
	d, ok := f.Detail.(*JPPhoneDetail)
	return d, ok
}

// JWTDetail returns the JWT-specific detail if this finding was produced by
// the JWT detector. Returns (nil, false) when not applicable.
func (f Finding) JWTDetail() (*JWTDetail, bool) {
	d, ok := f.Detail.(*JWTDetail)
	return d, ok
}

// AWSKeyDetail returns the AWS key-specific detail if this finding was produced by
// the AWSKey detector. Returns (nil, false) when not applicable.
func (f Finding) AWSKeyDetail() (*AWSKeyDetail, bool) {
	d, ok := f.Detail.(*AWSKeyDetail)
	return d, ok
}

// IBANDetail returns the IBAN-specific detail if this finding was produced by
// the IBAN detector. Returns (nil, false) when not applicable.
func (f Finding) IBANDetail() (*IBANDetail, bool) {
	d, ok := f.Detail.(*IBANDetail)
	return d, ok
}

// IPAddrDetail returns the IP address-specific detail if this finding was produced
// by the IPAddr detector. Returns (nil, false) when not applicable.
func (f Finding) IPAddrDetail() (*IPAddrDetail, bool) {
	d, ok := f.Detail.(*IPAddrDetail)
	return d, ok
}

// MyNumberDetail returns the My Number-specific detail if this finding was produced
// by the MyNumber detector. Returns (nil, false) when not applicable.
func (f Finding) MyNumberDetail() (*MyNumberDetail, bool) {
	d, ok := f.Detail.(*MyNumberDetail)
	return d, ok
}

// SWIFTBICDetail returns the SWIFT/BIC-specific detail if this finding was produced
// by the SWIFTBIC detector. Returns (nil, false) when not applicable.
func (f Finding) SWIFTBICDetail() (*SWIFTBICDetail, bool) {
	d, ok := f.Detail.(*SWIFTBICDetail)
	return d, ok
}

// ABARoutingDetail returns the ABA routing-specific detail if this finding was produced
// by the ABARouting detector. Returns (nil, false) when not applicable.
func (f Finding) ABARoutingDetail() (*ABARoutingDetail, bool) {
	d, ok := f.Detail.(*ABARoutingDetail)
	return d, ok
}

// UKSortCodeDetail returns the UK sort code-specific detail if this finding was produced
// by the UKSortCode detector. Returns (nil, false) when not applicable.
func (f Finding) UKSortCodeDetail() (*UKSortCodeDetail, bool) {
	d, ok := f.Detail.(*UKSortCodeDetail)
	return d, ok
}

// CVVDetail returns the CVV/CVC-specific detail if this finding was produced
// by the CVV detector. Returns (nil, false) when not applicable.
func (f Finding) CVVDetail() (*CVVDetail, bool) {
	d, ok := f.Detail.(*CVVDetail)
	return d, ok
}

// CardExpiryDetail returns the card expiry-specific detail if this finding was produced
// by the CardExpiry detector. Returns (nil, false) when not applicable.
func (f Finding) CardExpiryDetail() (*CardExpiryDetail, bool) {
	d, ok := f.Detail.(*CardExpiryDetail)
	return d, ok
}

// PaymentTokenDetail returns the payment token-specific detail if this finding was produced
// by the PaymentToken detector. Returns (nil, false) when not applicable.
func (f Finding) PaymentTokenDetail() (*PaymentTokenDetail, bool) {
	d, ok := f.Detail.(*PaymentTokenDetail)
	return d, ok
}

// BankAccountDetail returns the bank account-specific detail if this finding was produced
// by the BankAccount detector. Returns (nil, false) when not applicable.
func (f Finding) BankAccountDetail() (*BankAccountDetail, bool) {
	d, ok := f.Detail.(*BankAccountDetail)
	return d, ok
}

// ACHTraceDetail returns the ACH trace-specific detail if this finding was produced
// by the ACHTrace detector. Returns (nil, false) when not applicable.
func (f Finding) ACHTraceDetail() (*ACHTraceDetail, bool) {
	d, ok := f.Detail.(*ACHTraceDetail)
	return d, ok
}

// MerchantIDDetail returns the merchant/terminal ID-specific detail if this finding was
// produced by the MerchantID detector. Returns (nil, false) when not applicable.
func (f Finding) MerchantIDDetail() (*MerchantIDDetail, bool) {
	d, ok := f.Detail.(*MerchantIDDetail)
	return d, ok
}

// Level returns the confidence level of this finding as a human-readable
// threshold value. This is useful when exact confidence scores are not needed
// and a categorical assessment (high/medium/low) is sufficient.
//
// Thresholds:
//   - [ConfidenceHigh]: Confidence >= 0.8
//   - [ConfidenceMedium]: 0.4 <= Confidence < 0.8
//   - [ConfidenceLow]: Confidence < 0.4
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

// Kind returns the semantic category of this finding (e.g., [KindFinancial],
// [KindPII], [KindCredential]). This enables downstream consumers to classify
// findings by broad category for logging, auditing, and statistics without
// switching on all individual detector names.
//
// Custom detectors not registered in the built-in kind mapping return ""
// (empty SensitiveKind).
//
//	if f.Kind() == detector.KindCredential {
//	    alertSecurityTeam(f)
//	}
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
)
