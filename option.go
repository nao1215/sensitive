package sensitive

import "github.com/nao1215/sensitive/detector"

// Option configures a [Scanner] through [NewScanner].
type Option func(*Scanner)

// WithPAN enables [detector.PAN] detection.
func WithPAN() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewPAN())
	}
}

// WithEmail enables [detector.Email] detection.
func WithEmail() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewEmail())
	}
}

// WithJPPhone enables [detector.JPPhone] detection.
func WithJPPhone() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewJPPhone())
	}
}

// WithMyNumber enables [detector.MyNumber] detection.
func WithMyNumber() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewMyNumber())
	}
}

// WithJWT enables [detector.JWT] detection.
func WithJWT() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewJWT())
	}
}

// WithAWSKey enables [detector.AWSKey] detection.
func WithAWSKey() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewAWSKey())
	}
}

// WithIBAN enables [detector.IBAN] detection.
func WithIBAN() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewIBAN())
	}
}

// WithIPAddr enables [detector.IPAddr] detection.
func WithIPAddr() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewIPAddr())
	}
}

// WithSWIFTBIC enables [detector.SWIFTBIC] detection.
func WithSWIFTBIC() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewSWIFTBIC())
	}
}

// WithABARouting enables [detector.ABARouting] detection.
func WithABARouting() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewABARouting())
	}
}

// WithUKSortCode enables [detector.UKSortCode] detection.
func WithUKSortCode() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewUKSortCode())
	}
}

// WithCVV enables [detector.CVV] detection.
func WithCVV() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewCVV())
	}
}

// WithCardExpiry enables [detector.CardExpiry] detection.
func WithCardExpiry() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewCardExpiry())
	}
}

// WithPaymentToken enables [detector.PaymentToken] detection.
func WithPaymentToken() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewPaymentToken())
	}
}

// WithBankAccount enables [detector.BankAccount] detection.
func WithBankAccount() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewBankAccount())
	}
}

// WithACHTrace enables [detector.ACHTrace] detection.
func WithACHTrace() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewACHTrace())
	}
}

// WithMerchantID enables [detector.MerchantID] detection.
func WithMerchantID() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewMerchantID())
	}
}

// WithBTC enables [detector.BTC] detection.
func WithBTC() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewBTC())
	}
}

// WithETH enables [detector.ETH] detection.
func WithETH() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewETH())
	}
}

// WithGitHubToken enables [detector.GitHubToken] detection.
func WithGitHubToken() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewGitHubToken())
	}
}

// WithSlackToken enables [detector.SlackToken] detection.
func WithSlackToken() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewSlackToken())
	}
}

// WithGoogleAPIKey enables [detector.GoogleAPIKey] detection.
func WithGoogleAPIKey() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewGoogleAPIKey())
	}
}

// WithPrivateKeyPEM enables [detector.PrivateKeyPEM] detection.
func WithPrivateKeyPEM() Option {
	return func(s *Scanner) {
		s.detectors = append(s.detectors, detector.NewPrivateKeyPEM())
	}
}

// WithAll enables every built-in detector, including context-based detectors that can produce false positives. Select individual With options when those matches are unwanted.
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
			detector.NewGitHubToken(),
			detector.NewSlackToken(),
			detector.NewGoogleAPIKey(),
			detector.NewPrivateKeyPEM(),
		)
	}
}

// WithSortByPosition orders findings by start offset ascending, then confidence descending and detector name.
func WithSortByPosition() Option {
	return func(s *Scanner) {
		s.sortByPosition = true
	}
}

// WithoutDedup retains overlapping findings from all enabled detectors.
func WithoutDedup() Option {
	return func(s *Scanner) {
		s.skipDedup = true
	}
}

// WithMinConfidence keeps findings with confidence >= threshold after deduplication and sorting. Values below 0 become 0, values above 1 become 1, and 0 (the default) disables filtering.
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

// WithDetector registers d; a nil interface is ignored. See [Detector] for the hint and finding contracts.
func WithDetector(d Detector) Option {
	return func(s *Scanner) {
		if d == nil {
			return
		}
		s.detectors = append(s.detectors, d)
	}
}
