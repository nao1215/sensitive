// Package detector provides built-in sensitive-data detectors and the [Detector] extension interface. Each detector type documents its validation steps and confidence score; the root sensitive package composes detectors into a scanner.
//
// # Full-Width Digits and Boundaries
//
// [PAN], [JPPhone], [MyNumber], [ABARouting], and [BankAccount] use [NormalizeFullWidthDigits] before extraction. For example, ０９０－１２３４－５６７８ and 口座番号 １２３４５６７８ are recognized. IBAN and UK sort codes use ASCII formats; CVV, card expiry, ACH trace, and merchant IDs also do not normalize full-width digits. Findings retain the original bytes and offsets.
//
// Leading percent-encoded log/query separators (whitespace, quotes, brackets, colon, comma, semicolon, equals, ampersand, and question mark) delimit values like literal separators. Encoded word characters and malformed escapes do not relax boundary checks.
//
// # Finding Details
//
// [Finding.Detail] holds different detail types in one result slice. Its typed accessor methods avoid direct type assertions; [Finding.Is] and the Is* methods check detector names, while [Finding.Kind] supplies a broad category. Runnable examples show classification, confidence levels, and detail access.
package detector
