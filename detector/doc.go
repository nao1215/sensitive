// Package detector provides individual sensitive data detector implementations
// for the sensitive library. Each detector targets a specific type of sensitive
// data (e.g., credit card numbers, email addresses, phone numbers) and implements
// the sensitive.Detector interface.
//
// Detectors use a multi-stage approach to minimize false positives:
//
//  1. Hint-based pre-filtering via the Hints() method, enabling the Scanner
//     to quickly skip non-matching input using bytes.Contains.
//  2. Dedicated parsers that scan byte sequences directly, avoiding expensive
//     regular expression evaluation when possible.
//  3. Domain rule validation (BIN prefix checks, Luhn algorithm, check digit
//     verification, etc.) to confirm that candidates are genuine.
//
// # Available Detectors
//
//   - [PAN]: Credit card number detection with BIN prefix and Luhn validation
//   - [Email]: Email address detection using '@' pivot scanning
//   - [JPPhone]: Japanese phone number detection (landline, mobile, IP, toll-free)
//   - [MyNumber]: Japanese My Number (individual number) with check digit validation
//   - [JWT]: JSON Web Token detection with header structure validation
//   - [AWSKey]: AWS Access Key ID detection (AKIA/ASIA prefix)
//   - [IBAN]: International Bank Account Number with MOD 97 validation
//   - [IPAddr]: IPv4 and IPv6 address detection
//   - [SWIFTBIC]: SWIFT/BIC code detection with country code validation
//   - [ABARouting]: US ABA routing transit number with checksum validation
//   - [UKSortCode]: UK bank sort code detection (XX-XX-XX format)
//   - [CVV]: Card verification value (CVV/CVC) detection with context keywords
//   - [CardExpiry]: Payment card expiration date detection with context keywords
//   - [PaymentToken]: Payment processor token detection (Stripe, PayPal, Square)
//   - [BankAccount]: Bank account number detection using context keywords (weak detection)
//   - [ACHTrace]: ACH trace number detection with context keywords
//   - [MerchantID]: Merchant ID and terminal ID detection with context keywords
//   - [Regex]: User-defined regular expression detector for custom patterns
//
// # Full-Width Digit Normalization
//
// The [NormalizeFullWidthDigits] utility converts full-width digits (U+FF10-U+FF19)
// and full-width hyphens to their half-width equivalents, enabling detection of
// sensitive data written in Japanese full-width characters.
package detector
