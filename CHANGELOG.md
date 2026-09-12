# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-09-12

### Changed

- The supported Go floor is 1.22 instead of 1.24. Nothing in the tree needs a newer Go: 1.22 is where the detectors' range-over-int stops compiling, so that is the real minimum, and two more Go releases can now use this library. The unit-test matrix runs that floor and the newest release, and the GitHub Actions pins move to `actions/checkout@v7` / `actions/setup-go@v7`.
- CI cross-builds the module for FreeBSD, OpenBSD and NetBSD. A library is reached by `go get` from whatever machine its caller has, and nothing was checking that those three still compile.

### Removed

- The Go Report Card badge. The service is retired and its badge now answers `go report: retired`, which is a line of README saying nothing about this library.

## [0.1.0] - 2026-07-01

### Added

- **Developer credential detectors**: four new detectors for secrets commonly
  leaked in source, CI logs, and command lines.
  - `WithGitHubToken()` (`NameGitHubToken`): classic GitHub tokens
    (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36 base62 chars) and fine-grained PATs
    (`github_pat_` + 22+ chars). Detail: `GitHubTokenDetail{TokenType}`.
  - `WithSlackToken()` (`NameSlackToken`): Slack API tokens
    (`xoxb-`/`xoxp-`/`xoxa-`/`xoxo-`/`xoxr-`/`xoxs-`). Detail:
    `SlackTokenDetail{TokenType}`.
  - `WithGoogleAPIKey()` (`NameGoogleAPIKey`): Google API keys (`AIza` + 35
    chars). Detail: `GoogleAPIKeyDetail`.
  - `WithPrivateKeyPEM()` (`NamePrivateKeyPEM`): PEM private key headers
    (`-----BEGIN [ALGO ]PRIVATE KEY-----` for RSA/EC/DSA/OpenSSH/PKCS#8). Detail:
    `PrivateKeyPEMDetail{KeyType}`.

  All four are classified as `KindCredential`, use hint-based pre-filtering with
  dedicated byte scanners (no regular expressions), and are included in
  `WithAll()`. Findings expose `Is*` predicates and `*Detail()` accessors
  consistent with the existing detectors.

## [0.0.3] - 2026-02-10

### Fixed

- **ScanLines buffer limit increased to 1 MB** ([6ee98e3](https://github.com/nao1215/sensitive/commit/6ee98e3)): The internal `bufio.Scanner` buffer now starts at 64 KB and grows up to 1 MB (previously limited to the default 64 KB). Lines exceeding 1 MB return `bufio.ErrTooLong`. The doc comment now documents this limitation explicitly.
- **ScanLines callback receives a safe copy of line bytes** ([216ce24](https://github.com/nao1215/sensitive/commit/216ce24)): The `line` slice passed to the ScanLines callback is now an independent copy, safe to retain after the callback returns. Previously, the slice pointed into the `bufio.Scanner` internal buffer, which was overwritten on the next `Scan()` call.
- **Confidence values clamped to [0, 1]** ([2802566](https://github.com/nao1215/sensitive/commit/2802566)): `WithMinConfidence` and `detector.NewRegex` now clamp the confidence parameter to the valid range. Values below 0 are treated as 0 and values above 1 are treated as 1.

### Changed

- **Clarified minConfidence ordering in documentation** ([cc8d13d](https://github.com/nao1215/sensitive/commit/cc8d13d)): The `Scanner.Scan` and `WithMinConfidence` doc comments now explicitly state that the confidence threshold is applied after deduplication and sorting, so dedup always sees the full candidate set.
- **Extracted duplicated ASCII helpers to `internal/ascii`** ([50a6846](https://github.com/nao1215/sensitive/commit/50a6846)): `hasASCIILetter`, `asciiLowerCopy`, and `toLowerASCII` were duplicated between `scanner.go` and `detector/context.go`. They are now shared via the `internal/ascii` package, eliminating the risk of future divergence.
- **Pre-computed keyword cache for context-based detectors** ([7d56c0f](https://github.com/nao1215/sensitive/commit/7d56c0f)): Introduced `keywordSet` type that pre-computes lowered keyword forms once at initialization. Context-based detectors (CVV, ACH, card expiry, merchant ID, bank account) no longer call `ascii.LowerCopy` per keyword on every `Scan` invocation.

### Tests

- **ScanLines ErrTooLong regression test** ([b71bf3d](https://github.com/nao1215/sensitive/commit/b71bf3d)): Verifies that lines exceeding the 1 MB buffer return `bufio.ErrTooLong`.
- **ScanLines buffer copy safety test** ([5e24472](https://github.com/nao1215/sensitive/commit/5e24472)): Verifies that retained `line` slices from the callback are not corrupted by subsequent scans.
- **WithMinConfidence boundary value tests** ([cf0a3f0](https://github.com/nao1215/sensitive/commit/cf0a3f0)): Verifies that a finding with confidence exactly equal to the threshold is included, and one just below is excluded.
- **RawValue == input[Start:End] invariant test** ([54eaa2c](https://github.com/nao1215/sensitive/commit/54eaa2c)): Verifies across all built-in detectors that every finding's `RawValue` matches the corresponding `input[Start:End]` slice, preventing mask output corruption.

## [0.0.2] - 2026-02-08

### Added

- **Stream scanning API** ([06cc2b1](https://github.com/nao1215/sensitive/commit/06cc2b1)): `ScanReader(io.Reader)` for in-memory scanning and `ScanLines(io.Reader, callback)` for memory-efficient line-by-line streaming. Ideal for log files and large text streams.
- **Bitcoin (BTC) address detector** ([a35fec8](https://github.com/nao1215/sensitive/commit/a35fec8)): Detects P2PKH (prefix '1'), P2SH (prefix '3'), Bech32 SegWit v0 (prefix 'bc1q'), and Bech32m Taproot v1–v16 (prefix 'bc1p') addresses. Validates Base58Check (double SHA-256 checksum) for legacy addresses and Bech32/Bech32m polynomial checksums (BIP-173/BIP-350) for SegWit/Taproot addresses. Confidence: 0.95.
- **Ethereum (ETH) address detector** ([a35fec8](https://github.com/nao1215/sensitive/commit/a35fec8)): Detects Ethereum addresses (0x + 40 hex characters). Validates EIP-55 mixed-case checksums using Keccak-256. Confidence: 0.80 for all-lowercase/all-uppercase, 0.95 for EIP-55 validated addresses.
- **Keccak-256 hash implementation** ([a35fec8](https://github.com/nao1215/sensitive/commit/a35fec8)): Minimal Keccak-f[1600] sponge construction for EIP-55 checksum validation. Zero external dependencies — uses only the Go standard library.
- **`WithBTC()` and `WithETH()` scanner options** ([a35fec8](https://github.com/nao1215/sensitive/commit/a35fec8)): Enable individual cryptocurrency address detection.
- **`BTCDetail()` and `ETHDetail()` finding accessors** ([a35fec8](https://github.com/nao1215/sensitive/commit/a35fec8)): Type-safe access to detector-specific details (address type, EIP-55 validation status).
- **`IsBTC()` and `IsETH()` finding helpers** ([a35fec8](https://github.com/nao1215/sensitive/commit/a35fec8)): Quick detector type checks.
- **Kind mapping** ([a35fec8](https://github.com/nao1215/sensitive/commit/a35fec8)): Both BTC and ETH are classified as `KindFinancial`.
- **Japanese phone number format expansion** ([46d2db8](https://github.com/nao1215/sensitive/commit/46d2db8)): Added IP phone (050), M2M/IoT (020), and FMC service (060) prefix detection. Enhanced `JPPhoneDetail` with `JPPhoneType` classification.
- **Bank account full-width digit support** ([46d2db8](https://github.com/nao1215/sensitive/commit/46d2db8)): Bank account detector now normalizes full-width digits for Japanese input.

### Changed

- **Reduced cyclomatic complexity** ([4b0e022](https://github.com/nao1215/sensitive/commit/4b0e022)): Refactored detector implementations (PAN, email, JWT, IBAN, IP address, sort code, SWIFT/BIC, etc.) and scanner internals to reduce cyclomatic complexity and improve maintainability.

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

[0.0.3]: https://github.com/nao1215/sensitive/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/nao1215/sensitive/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/nao1215/sensitive/releases/tag/v0.0.1
