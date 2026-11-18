package embargo

// Kind identifies a built-in or application-defined detection family.
//
// Each built-in constant states what it matches, how it is checked, its scores and
// whether NewScanner enables it; WithKinds and WithAll change that selection. A
// business label is a word such as order, invoice, tracking or version right before
// a candidate, and it lowers numeric scores. Scan also reads full-width digits,
// Unicode dashes and one layer of percent-encoding; the [detector rules] give the
// exact normalization. A match does not establish that an account, credential or
// identity exists.
//
// [detector rules]: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#rules-by-kind
type Kind string

// Finding locates a sensitive-data candidate in the original input without retaining its value.
type Finding struct {
	// Kind identifies the detection family.
	Kind Kind
	// Start is the inclusive byte offset.
	Start int
	// End is the exclusive byte offset.
	End int
	// Confidence is a heuristic score in [0,1], not a probability.
	Confidence float64
}

const (
	// KindServiceToken covers provider-prefixed secrets and webhook credential paths; prefix, alphabet and length checks yield 0.95 without a keyword or remote authentication. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindservicetoken (NewScanner default: on).
	KindServiceToken Kind = "service_token"
	// KindHighEntropy looks for unlabeled runs of 32–256 ASCII letters, digits, _, - or +; Shannon entropy of at least 4.5 bits per byte and three of lowercase, uppercase, digit and symbol classes yield 0.3. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindhighentropy (NewScanner default: off).
	KindHighEntropy Kind = "high_entropy"
	// KindCredential locates nonempty assignment values, Authorization credentials and URL/DSN passwords; delimiter and quoting checks give 0.95, preserving labels, initial auth schemes, usernames and hosts. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindcredential (NewScanner default: on).
	KindCredential Kind = "credential"
	// KindPAN finds 13–19 digits with Visa, Mastercard, Amex, JCB, Discover, Diners or UnionPay prefixes; Luhn plus issuer length scores 1.0 and an attached business label 0.4; a failed checksum is not a card, nor is a 13-digit number that also passes the EAN-13 check, such as a JAN product code. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindpan (NewScanner default: on).
	KindPAN Kind = "pan"
	// KindEmail extracts ASCII local parts using letters, digits and .+-_ before @ or the full-width ＠ and dotted domains using letters, digits and .-; structure checks score 0.7 or 0.8 for an unknown TLD and 0.9 or 1.0 for a known TLD. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindemail (NewScanner default: on).
	KindEmail Kind = "email"
	// KindJPPhone recognizes 10- or 11-digit Japanese numbers beginning with 0 or written as +81 without the leading 0, allowing spaces, hyphens and parentheses; prefix/length checks score landlines 0.8, other accepted types 0.9, and business labels 0.4. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindjpphone (NewScanner default: on).
	KindJPPhone Kind = "phone_jp"
	// KindUSPhone recognizes separated ten-digit North American numbers such as (202) 555-0123 or 202.555.0123, with an optional +1 or 1 country code; numbering-plan and matching-separator checks score 0.7, 0.9 after a phone, tel, mobile, cell, fax, call or contact label, and 0.4 after a business label. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindusphone (NewScanner default: on).
	KindUSPhone Kind = "phone_us"
	// KindMyNumber recognizes 12 digits with optional spaces or hyphens as Japanese individual-number candidates; the weighted MOD 11 check gives 0.95 without requiring a keyword; a contiguous 12-digit account field of a syntactic ARN with an AWS partition and a value labeled as a record identifier, such as accountId, user_id, account, tracking or 注文番号, are excluded, while a My Number or 個人番号 label keeps it. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindmynumber (NewScanner default: on).
	KindMyNumber Kind = "mynumber"
	// KindJWT parses eyJ-prefixed base64url text with exactly two dots and nonempty header and payload segments; header checks yield 0.5, 0.7 or 0.8 with an empty signature, and 0.7, 0.9 or 1.0 otherwise. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindjwt (NewScanner default: on).
	KindJWT Kind = "jwt"
	// KindAWSKey identifies AKIA (long-term), ASIA (temporary), ABIA (STS service bearer) or ACCA (context-specific) followed by exactly 16 uppercase ASCII letters or digits (20 characters total); length, alphabet and alphanumeric boundary checks give 0.95 without a context keyword or authentication (NewScanner default: on).
	KindAWSKey Kind = "awskey"
	// KindIBAN accepts two ASCII country letters, two digits and an alphanumeric BBAN with optional internal spaces; country length and MOD 97 checks give 0.95, rejecting check digits 00, 01 and 99 without requiring a keyword. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindiban (NewScanner default: on).
	KindIBAN Kind = "iban"
	// KindIPAddr extracts dotted IPv4 decimal octets and colon-separated IPv6 hexadecimal text, including :: shorthand; net.ParseIP validation gives 0.8, excluding IPv4 addresses whose first octet is zero (the this-network block, which contains the unspecified address), the IPv6 unspecified address and loopback addresses with no keyword needed. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindipaddr (NewScanner default: on).
	KindIPAddr Kind = "ipaddr"
	// KindSWIFTBIC accepts 8 or 11 ASCII alphanumerics as four bank letters, two country letters, location and optional branch; country and structure checks give 0.85, with case ignored and no institution lookup. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindswiftbic (NewScanner default: on).
	KindSWIFTBIC Kind = "swiftbic"
	// KindABARouting selects 9 consecutive digits beginning 01–12, 21–32, 61–72 or 80 as US routing candidates; the repeating 3,7,1 weighted MOD 10 checksum must pass, giving 0.85 without a keyword. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindabarouting (NewScanner default: on).
	KindABARouting Kind = "aba_routing"
	// KindUKSortCode picks six digits in three pairs separated consistently by hyphens or spaces with matching separators, excluding all-zero codes; structure checks give 0.7, or 0.55 for contextual date-like candidates, without a checksum. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kinduksortcode (NewScanner default: on).
	KindUKSortCode Kind = "uk_sortcode"
	// KindCVV finds 3 or 4 consecutive digits within 30 bytes of a verification-code keyword end; length and non-overlap checks yield 0.85 without a checksum. The required keywords are cvv, cvc, cid, cvv2, cvc2, security code or セキュリティコード, with ASCII case ignored (NewScanner default: on).
	KindCVV Kind = "cvv"
	// KindCardExpiry reads MM/YY, MM/YYYY, MM-YY or MM-YYYY near expiration labels; month 01–12 and adjacent-digit checks yield 0.85, without checking whether the date is in the future. Search starts within 50 bytes before or after the required case-insensitive keyword exp, exp date, expiry, expires, expiration, expiration date, valid thru, valid through or 有効期限 (NewScanner default: on).
	KindCardExpiry Kind = "card_expiry"
	// KindPaymentToken covers Stripe identifiers and keys, PayPal PAYID- and Square sq0idp-/sq0csp- tokens; prefix and minimum-body checks yield 0.9 with no keyword or authentication. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindpaymenttoken (NewScanner default: on).
	KindPaymentToken Kind = "payment_token"
	// KindBankAccount looks for 4–17 consecutive digits within 50 bytes of a banking keyword end; length checks give 0.5, raised to 0.65 by nearby holder context, without a checksum. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindbankaccount (NewScanner default: on).
	KindBankAccount Kind = "bank_account"
	// KindACHTrace takes 15 consecutive digits within 50 bytes of an ACH or trace keyword end; prefix validation requires 01–12, 21–32, 61–72 or 80 and scores 0.75 without a checksum. Context is mandatory: ach, ach trace, trace number, trace no, trace # or trace# with ASCII case ignored (NewScanner default: on).
	KindACHTrace Kind = "ach_trace"
	// KindMerchantID finds 15 ASCII alphanumerics for merchant IDs or 8 consecutive digits at alphanumeric boundaries for terminal IDs; length and keyword-overlap checks give 0.7 without checksum validation. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindmerchantid (NewScanner default: on).
	KindMerchantID Kind = "merchant_id"
	// KindBTC recognizes mainnet 1/3 Base58 text of 25–34 characters or single-case bc1 text of 42 or 62 characters; Base58Check or Bech32/Bech32m checksum validation gives 0.95 without a keyword. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindbtc (NewScanner default: on).
	KindBTC Kind = "btc"
	// KindETH captures 0x or 0X followed by exactly 40 hexadecimal characters at identifier boundaries; uniform-case hex scores 0.8 without checksum validation, while mixed case must pass EIP-55 (Keccak-256) for 0.95, with no context keyword required (NewScanner default: on).
	KindETH Kind = "eth"
	// KindGitHubToken distinguishes classic ghp_/gho_/ghu_/ghs_/ghr_ tokens from github_pat_ tokens; body-length and token-boundary checks yield 0.95 without a keyword or authentication. Classic bodies require exactly 36 ASCII letters/digits; fine-grained bodies require at least 22 ASCII letters/digits/underscores (NewScanner default: on).
	KindGitHubToken Kind = "github_token"
	// KindSlackToken recognizes xoxb-, xoxp-, xoxa-, xoxo-, xoxr-, xoxs- and xoxe- followed by ASCII letters, digits or hyphens; a body of at least 10 characters and token-boundary checks yield 0.9, with no context keyword or authentication (NewScanner default: on).
	KindSlackToken Kind = "slack_token"
	// KindGoogleAPIKey looks for AIza followed by exactly 35 ASCII letters, digits, hyphens or underscores; the 39-character length and token-boundary checks give 0.9 without a keyword or authentication (NewScanner default: on).
	KindGoogleAPIKey Kind = "google_api_key"
	// KindPrivateKeyPEM covers -----BEGIN headers whose same-line content ends in PRIVATE KEY or equals PGP PRIVATE KEY BLOCK, closed by five hyphens; header grammar alone gives 0.99 without a keyword or key-material validation. Any algorithm text is accepted; the span extends through an identical -----END label when present, otherwise the span extends to end of input (NewScanner default: on).
	KindPrivateKeyPEM Kind = "private_key_pem"
)

const (
	// KindUSSSN recognizes 9 digits, either contiguous or grouped 3-2-4 with hyphens; field checks yield 0.6, or 0.4 under a business label, with no keyword or checksum required. Area 000, 666 and 900–999, group 00 and serial 0000 are rejected (NewScanner default: off).
	KindUSSSN Kind = "us_ssn"
	// KindUSITIN finds 9 digits starting with 9, optionally hyphenated 3-2-4; middle-group validation gives 0.6, or 0.4 under a business label, without a keyword or checksum. The fourth/fifth digits must be 50–65, 70–88, 90–92 or 94–99 (NewScanner default: off).
	KindUSITIN Kind = "us_itin"
	// KindUKNINO accepts two uppercase ASCII letters, six digits and a suffix A–D, optionally spaced into groups of 2 letters, 2/2/2 digits and 1 letter; prefix checks score 0.7, reduced to 0.4 by a business label, without requiring context or a checksum. Both prefix letters exclude D/F/I/Q/U/V, the second also excludes O, and BG/GB/KN/NK/NT/TN/ZZ are forbidden (NewScanner default: off).
	KindUKNINO Kind = "uk_nino"
	// KindUKNHS collects 10 digits, contiguous or spaced 3-3-4; weighted MOD 11 validation yields 0.95, or 0.4 with a business label, and needs no keyword. The first 9 digits use weights 10 down to 2, a check value of 10 is rejected, and repeated single-digit values are excluded (NewScanner default: off).
	KindUKNHS Kind = "uk_nhs"
	// KindIndiaAadhaar accepts 12 digits beginning 2–9, contiguous or spaced 4-4-4; Verhoeff checksum validation gives 0.95, lowered to 0.4 by business context, without a keyword. Repeated single-digit values are rejected (NewScanner default: off).
	KindIndiaAadhaar Kind = "in_aadhaar"
	// KindIndiaPAN recognizes five uppercase ASCII letters, four digits and one final uppercase letter; holder-type and nonzero-serial checks score 0.7, or 0.4 under a business label, with no keyword or checksum. The fourth letter must be P/C/H/A/B/G/J/L/F/T and the four digits cannot be 0000 (NewScanner default: off).
	KindIndiaPAN Kind = "in_pan"
	// KindBrazilCPF takes 11 digits, contiguous or formatted DDD.DDD.DDD-DD; both MOD 11 check digits must pass for 0.95, or 0.4 under a business label, without a keyword. Repeated digits are rejected; the first check weights the initial 9 digits from 10 down to 2 and the second weights the first 10 from 11 down to 2 (NewScanner default: off).
	KindBrazilCPF Kind = "br_cpf"
	// KindBrazilCNPJ admits 12 uppercase ASCII alphanumerics and two digits, contiguous or formatted CC.CCC.CCC/CCCC-DD; two MOD 11 checks give 0.95, or 0.4 with a business label, without requiring a keyword. Character values are ASCII minus 48, right-to-left weights cycle 2–9, and repeated single-character values are rejected (NewScanner default: off).
	KindBrazilCNPJ Kind = "br_cnpj"
	// KindChinaResidentID requires 17 digits followed by a digit or uppercase X, including a YYYYMMDD birth date; province, date, sequence and MOD 11-2 checks yield 0.95, or 0.4 under a business label, with no keyword. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindchinaresidentid (NewScanner default: off).
	KindChinaResidentID Kind = "cn_resident_id"
	// KindKoreaRRN reads 13 digits, contiguous or hyphenated 6-7, with a birth date and century/sex digit; the legacy weighted MOD 11 check scores 0.95, labeled check failures 0.6, and business labels 0.4. Full rules: https://github.com/nao1215/embargo/blob/main/doc/detectors.md#kindkorearrn (NewScanner default: off).
	KindKoreaRRN Kind = "kr_rrn"
	// KindCanadaSIN finds 9 digits starting with 1–7 or 9, contiguous or hyphenated 3-3-3; Luhn checksum validation yields 0.95, or 0.4 under a business label, without a keyword. Repeated single-digit values are excluded (NewScanner default: off).
	KindCanadaSIN Kind = "ca_sin"
)
