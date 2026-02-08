# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2026-02-08

Initial release of the `sensitive` library.

### Added

- **Core scanning engine** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Multi-stage filtering pipeline with hint-based pre-filter (SIMD-optimized `bytes.Contains`), detector execution, and result dedup/sort.
- **Scanner options**: `WithAll()`, individual `With*()` options, `WithSortByPosition()`, `WithoutDedup()`, `WithCustomDetector()` for user-defined detectors.
- **Confidence scoring**: Every finding includes a confidence level (0.0--1.0) based on structural validation, checksums, and context keywords.

#### Detectors

- **PAN (Payment Card Number)** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects Visa, Mastercard, Amex, Discover, JCB, Diners Club, and UnionPay card numbers with Luhn checksum validation. Supports hyphenated, spaced, and contiguous formats. Full-width digit normalization for Japanese input.
- **Email** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Heuristic email address detection using `@` as a pivot point. Validates local and domain parts, TLD, and RFC 5321 label boundary rules. Confidence boosted by known TLD matching.
- **Japanese Phone Number** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects mobile (090/080/070), landline (03/06/etc.), and toll-free (0120/0800) Japanese phone numbers. Full-width digit normalization. Prefix-based classification.
- **My Number (Japanese national ID)** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects 12-digit My Number with official check digit validation (modular arithmetic per specification). Context keyword support (Japanese/English).
- **JWT (JSON Web Token)** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects JWTs via the `eyJ` prefix (base64url of `{"`). Validates three-part structure, decodes header JSON, and extracts the `alg` field. Supports unsigned JWTs (alg:none, CVE-2015-9235). Leading boundary check prevents false matches inside longer base64url strings.
- **AWS Access Key** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects AWS access key IDs (`AKIA` prefix + 16 uppercase alphanumeric characters). Context keyword support for key/secret pairs.
- **IBAN (International Bank Account Number)** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects IBANs with ISO 13616 mod-97 checksum validation. Supports all standardized country code prefixes and lengths.
- **IP Address** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects IPv4 and IPv6 addresses. Uses `net.ParseIP` for validation. Boundary checks reject IPs embedded in identifiers (leading/trailing alphanumeric, `_`, `-`).
- **SWIFT/BIC** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects SWIFT/BIC codes (8 or 11 characters). Validates bank code, country code (ISO 3166-1 alpha-2), location code, and optional branch code structure.
- **US ABA Routing Number** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects 9-digit ABA routing transit numbers. Validates Federal Reserve routing symbol prefix (01-12, 21-32, 61-72, 80) and ABA checksum (3-7-1 weighted mod-10).
- **UK Sort Code** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects UK bank sort codes in `XX-XX-XX` or `XX XX XX` format. Date-like pattern disambiguation with context keyword fallback. Rejects all-zero sort codes (00-00-00).
- **CVV/CVC/CID** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Context-based detection of 3-4 digit card verification values near keywords (CVV, CVC, CID, security code, etc.). Japanese keyword support.
- **Card Expiry** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Context-based detection of card expiration dates (MM/YY, MM/YYYY, MM-YY). Validates month range (01-12) and year range. Japanese keyword support.
- **Payment Token** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Detects Stripe (`sk_live_`, `pk_live_`, `sk_test_`, `pk_test_`), Square (`sq0atp-`, `sq0csp-`), and PayPal (`access_token$`) API keys/tokens.
- **Bank Account** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Context-based weak detection of bank account numbers (4-17 digits) near banking keywords. Japanese and English keyword support. Holder name context boosts confidence.
- **ACH Trace Number** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Context-based detection of 15-digit ACH trace numbers. Validates ODFI routing prefix against Federal Reserve routing symbol ranges.
- **Merchant/Terminal ID** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Context-based detection of merchant IDs (MID) and terminal IDs (TID) near keywords. Validates alphanumeric sequences of 8-15 characters.
- **Custom Detector** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Users can register custom detectors implementing the `Detector` interface via `WithCustomDetector()`. A `RegexDetector` helper is provided for regex-based detection.

#### Masking

- **mask package** ([13fca9a](https://github.com/nao1215/sensitive/commit/13fca9a)): Optional masking helper with `Mask()` for single findings and `MaskAll()` for multiple findings. Built-in strategies: `StrategyFull` (full masking) and `StrategyPartial` (preserve first/last N characters).

#### Architecture

- **Zero external dependencies**: Uses only the Go standard library.
- **Multi-stage filtering**: Hint-based pre-filtering with case-insensitive ASCII matching skips detectors early, minimizing scan cost.
- **Pre-computed hint cache**: Hint lowercase normalization is computed once at `NewScanner` construction, not per-scan.
- **O(n log n) overlap detection**: Dedup uses confidence-descending greedy selection with binary search for overlap checking.
- **Full-width digit normalization**: Transparent handling of Japanese full-width digits (U+FF10--U+FF19) for PAN, phone, and My Number detection.
- **Deterministic output**: Findings are sorted by confidence (descending), then by byte offset and detector name for fully reproducible results.

[0.0.1]: https://github.com/nao1215/sensitive/releases/tag/v0.0.1
