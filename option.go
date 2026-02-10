package sensitive

import "github.com/nao1215/sensitive/detector"

// Option is a function that configures a Scanner.
// Options are passed to [NewScanner] to enable specific detectors.
type Option func(*Scanner)

// WithPAN enables credit card number (PAN) detection.
// PAN detection uses BIN prefix matching and the Luhn algorithm
// to validate detected numbers, providing high-confidence results.
func WithPAN() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewPAN())
	}
}

// WithEmail enables email address detection.
// Email detection uses '@' as a pivot point and scans forward/backward
// to identify the local part and domain, then validates the structure.
func WithEmail() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewEmail())
	}
}

// WithJPPhone enables Japanese phone number detection.
// It recognizes landline (03-xxxx-xxxx), mobile (090-xxxx-xxxx),
// IP phone (050-xxxx-xxxx), and toll-free (0120-xxx-xxx) formats.
func WithJPPhone() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewJPPhone())
	}
}

// WithMyNumber enables Japanese My Number (individual number) detection.
// My Number is a 12-digit number with a check digit. The detector
// validates the check digit algorithm to reduce false positives.
func WithMyNumber() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewMyNumber())
	}
}

// WithJWT enables JSON Web Token detection.
// JWT detection looks for the characteristic "eyJ" prefix (base64 of "{")
// and validates the three-part structure (header.payload.signature).
func WithJWT() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewJWT())
	}
}

// WithAWSKey enables AWS Access Key ID detection.
// AWS keys always start with "AKIA" (long-term) or "ASIA" (temporary STS).
func WithAWSKey() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewAWSKey())
	}
}

// WithIBAN enables International Bank Account Number detection.
// IBAN detection validates the country code, length, and MOD 97 check digit.
func WithIBAN() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewIBAN())
	}
}

// WithIPAddr enables IP address (IPv4 and IPv6) detection.
func WithIPAddr() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewIPAddr())
	}
}

// WithSWIFTBIC enables SWIFT/BIC code detection.
// SWIFT/BIC codes are 8 or 11 character identifiers used for international
// wire transfers. Detection validates the format and ISO 3166-1 country code.
func WithSWIFTBIC() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewSWIFTBIC())
	}
}

// WithABARouting enables US ABA routing transit number detection.
// ABA routing numbers are 9-digit identifiers with a checksum used for
// ACH transfers, wire transfers, and check processing.
func WithABARouting() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewABARouting())
	}
}

// WithUKSortCode enables UK bank sort code detection.
// Sort codes are 6-digit numbers in XX-XX-XX format that identify bank branches.
func WithUKSortCode() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewUKSortCode())
	}
}

// WithCVV enables CVV/CVC/CID detection.
// Card verification values are 3-4 digit security codes on payment cards.
// Detection requires context keywords (e.g., "CVV", "security code") nearby.
func WithCVV() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewCVV())
	}
}

// WithCardExpiry enables payment card expiration date detection.
// Expiry dates are formatted as MM/YY or MM/YYYY. Detection requires context
// keywords (e.g., "exp", "expiry", "有効期限") nearby.
func WithCardExpiry() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewCardExpiry())
	}
}

// WithPaymentToken enables payment processor token detection.
// Detects API tokens from Stripe (sk_live_, pk_live_, tok_, etc.),
// PayPal (PAYID-), and Square (sq0idp-, sq0csp-).
func WithPaymentToken() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewPaymentToken())
	}
}

// WithBankAccount enables bank account number detection (context-based).
// This is a weak detector that looks for digit sequences near banking keywords
// (e.g., "口座番号", "bank account"). Confidence is intentionally lower (0.5-0.65)
// because bank account numbers have no universal format or checksum.
func WithBankAccount() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewBankAccount())
	}
}

// WithACHTrace enables ACH trace number detection.
// ACH trace numbers are 15-digit identifiers used to track ACH transactions.
// Detection requires context keywords (e.g., "ACH", "trace") nearby.
func WithACHTrace() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewACHTrace())
	}
}

// WithMerchantID enables merchant ID and terminal ID detection.
// MIDs are typically 15 alphanumeric characters and TIDs are 8 digits.
// Detection requires context keywords (e.g., "merchant ID", "TID") nearby.
func WithMerchantID() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewMerchantID())
	}
}

// WithBTC enables Bitcoin address detection.
// BTC detection supports P2PKH (prefix '1'), P2SH (prefix '3'),
// Bech32 SegWit v0 (prefix 'bc1q'), and Bech32m Taproot v1 (prefix 'bc1p').
// Addresses are validated using Base58Check (double SHA-256) or Bech32/Bech32m
// polynomial checksums.
func WithBTC() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewBTC())
	}
}

// WithETH enables Ethereum address detection.
// ETH detection recognizes 42-character addresses (0x + 40 hex chars).
// Mixed-case addresses are validated against the EIP-55 checksum
// using Keccak-256.
func WithETH() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewETH())
	}
}

// WithAll enables all built-in detectors.
// This is a convenience option equivalent to enabling each detector individually.
func WithAll() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors,
			detector.NewPAN(),
			detector.NewEmail(),
			detector.NewJPPhone(),
			detector.NewMyNumber(),
			detector.NewJWT(),
			detector.NewAWSKey(),
			detector.NewIBAN(),
			detector.NewIPAddr(),
			detector.NewSWIFTBIC(),
			detector.NewABARouting(),
			detector.NewUKSortCode(),
			detector.NewCVV(),
			detector.NewCardExpiry(),
			detector.NewPaymentToken(),
			detector.NewBankAccount(),
			detector.NewACHTrace(),
			detector.NewMerchantID(),
			detector.NewBTC(),
			detector.NewETH(),
		)
	}
}

// WithSortByPosition configures the Scanner to return findings sorted by
// their byte offset (Start position, ascending) instead of the default
// confidence-descending order. This is useful when the caller needs to
// process findings in the order they appear in the original text.
func WithSortByPosition() Option {
	return func(s *Scanner) {
		s.sortByPosition = true
	}
}

// WithoutDedup disables the default deduplication of overlapping findings.
// By default, when two findings overlap in byte position, only the one with
// the highest confidence is kept. With this option, all findings are returned,
// which is useful when the caller needs to see every detection from every
// detector, even if they overlap.
//
//	scanner := sensitive.NewScanner(sensitive.WithAll(), sensitive.WithoutDedup())
func WithoutDedup() Option {
	return func(s *Scanner) {
		s.skipDedup = true
	}
}

// WithMinConfidence sets the minimum confidence threshold for reported findings.
// Findings with confidence below the threshold are filtered out after detection
// and deduplication. This allows callers to select a strict mode (e.g., 0.8 for
// high-confidence only) or a loose mode (e.g., 0.4 to include medium-confidence
// matches).
//
// The threshold is clamped to the [0, 1] range. Values below 0 are treated as 0
// and values above 1 are treated as 1.
//
// A value of 0 (the default) disables filtering and returns all findings.
//
//	// Strict mode: only high-confidence findings.
//	scanner := sensitive.NewScanner(sensitive.WithAll(), sensitive.WithMinConfidence(0.8))
//
//	// Loose mode: include medium-confidence and above.
//	scanner := sensitive.NewScanner(sensitive.WithAll(), sensitive.WithMinConfidence(0.4))
func WithMinConfidence(threshold float64) Option {
	return func(s *Scanner) {
		s.minConfidence = clampConfidence(threshold)
	}
}

// clampConfidence restricts v to the [0, 1] range.
func clampConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// WithDetector adds a custom Detector to the Scanner.
// This allows users to extend the Scanner with their own detection logic.
// If d is nil, the option is a no-op (the nil detector is silently ignored).
//
//	customDetector := detector.NewRegex(
//	    "internal_id",
//	    regexp.MustCompile(`PROJ-\d{6}`),
//	    [][]byte{[]byte("PROJ-")},
//	    0.8,
//	)
//	scanner := sensitive.NewScanner(sensitive.WithDetector(customDetector))
func WithDetector(d Detector) Option {
	return func(s *Scanner) {
		if d == nil {
			return
		}
		s.detectors = append(s.detectors, d)
	}
}
