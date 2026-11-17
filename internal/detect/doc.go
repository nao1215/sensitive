// Package detect provides built-in sensitive-data detectors and the [Detector] extension interface. Each detector type documents its validation steps and confidence score; the root embargo package composes detectors into a scanner.
//
// # Full-Width Digits and Boundaries
//
// [PAN], [JPPhone], [MyNumber], [ABARouting], and [BankAccount] normalize full-width digits before extraction, using [NormalizeFullWidthDigits] for non-ASCII input and an allocation-free identity path for ASCII input. For example, ０９０－１２３４－５６７８ and 口座番号 １２３４５６７８ are recognized. IBAN and UK sort codes use ASCII formats; CVV, card expiry, ACH trace, and merchant IDs also do not normalize full-width digits. Findings retain the original bytes and offsets.
//
// Leading percent-encoded log/query separators (whitespace, quotes, brackets, colon, comma, semicolon, equals, ampersand, and question mark) delimit values like literal separators. Encoded word characters and malformed escapes do not relax boundary checks.
//
// Findings contain only a detector name, original byte span and confidence. Validation helpers own checksum and issuer decisions; no raw value or diagnostic detail is retained.
package detect
