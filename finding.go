package embargo

// Kind identifies a built-in or application-defined detection family.
//
// Built-in comments state matching, validation, heuristic scores and the selection
// made by NewScanner without options; WithKinds and WithAll override that selection.
// A business label means order, invoice, tracking, version, build, serial or
// shipment immediately before a candidate in the same field, within 48 bytes,
// optionally followed by id, number, ref or code; ASCII case is ignored.
// Numeric normalization accepts full-width digits and Unicode dash variants for
// PAN, JPPhone, MyNumber, ABARouting, BankAccount and the eleven country kinds.
// Built-ins except Credential ignore interior non-ASCII Unicode Pd, Zs, Cf and
// Sm intersected with Dash in token runs; ASCII space/hyphen remain delimiters.
// U+30FC remains a legacy numeric hyphen. See doc/policies.md for the allow list.
// Scan decodes one percent-encoding layer for every built-in except Credential.
// These checks do not establish that an account, credential or identity exists.
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
	// KindServiceToken covers provider-prefixed secrets and webhook credential paths; prefix, alphabet and length checks yield 0.95 without a keyword or remote authentication. ASCII letters, digits, _ and - form bodies of at least 16 bytes after sk-proj-, sk-svcacct-, sk-ant-api03-, sk-ant-admin01-, sk-admin-, sk_live_, rk_live_, whsec_, glpat-, npm_, pypi- or GOCSPX-, and GitLab glcbt-, gldt-, glffct-, glft-, glimt-, glrt-, glsoat-, glagent-, gloas- and GR1348941 bodies of at least 20 bytes may end in dot-separated routing parts; SG. requires 22 and 43 such bytes separated by a dot or 66 bytes that may include = and dots. About 70 further layouts (DigitalOcean, Shopify, HashiCorp Vault and Terraform, Databricks, Doppler, Dynatrace, Postman, Pulumi, Sentry, Grafana, Hugging Face, New Relic, Twilio API keys, Microsoft Entra client secrets, Telegram bots, MaxMind, Mailchimp, Facebook app tokens and others) fix the body alphabet and length per prefix as listed at https://github.com/nao1215/embargo/blob/main/doc/credentials.md; a body made of one repeated byte, such as xxxx, is a placeholder and is not reported. Slack https://hooks.slack.com/ or hooks.slack-gov.com URLs (http, https or no scheme) report the path after services/ (three parts), workflows/ or triggers/ (three or four parts) when parts have at least 2 bytes and the last at least 16, and Microsoft Teams *.webhook.office.com/webhookb2/ URLs report the path containing /IncomingWebhook/ (NewScanner default: on).
	KindServiceToken Kind = "service_token"
	// KindHighEntropy looks for unlabeled runs of 32–256 ASCII letters, digits, _, - or +; Shannon entropy of at least 4.5 bits per byte and three of lowercase, uppercase, digit and symbol classes yield 0.3. No keyword is required; slash/backslash-adjacent or dotted path components and assignments to id, requestid, traceid, spanid, commit, sha, hash, checksum or uuid (case and key separators ignored) are excluded (NewScanner default: off).
	KindHighEntropy Kind = "high_entropy"
	// KindCredential locates nonempty assignment values, Authorization credentials and URL/DSN passwords; delimiter and quoting checks give 0.95, preserving labels, initial auth schemes, usernames and hosts. Required assignment keys are password, passwd, secret, token, api_key, authorization, proxy-authorization, cookie, set-cookie, access_token, refresh_token, id_token, x-api-key, DB_PASSWORD, Private-Token, PGPASSWORD, X-Amz-Signature, sig, AccountKey, SharedAccessSignature, aws_secret_access_key, SecretAccessKey, private_key, client_secret, TWILIO_AUTH_TOKEN or auth_token, plus keys whose final separator/camel-case segment is password, passwd, secret, token, credential or auth, or key preceded by api, secret, private, access or account (ASCII case and _, -, dot or space variants, optionally followed by a number such as api_token_2); =, :, :=, ::=, :::=, ?=, +=, ||=, spaced .= or => introduces the value, a Go string or []byte type between the key and = and a string type annotation (name: String = value) are skipped, PHP print_r [key] => value is accepted, XML elements named by a key (including a namespace prefix) report their trimmed text content when the matching closing tag follows, Go/JSON quote, hexadecimal/Unicode quote and backslash escapes are scanned through four string layers with original offsets, quoted Bearer/Basic values need no key, fmt map/slice and Go typed literal values include all elements without decoding byte lists, unquoted values stop at field delimiters, fmt fields retain spaces until the next field, indented YAML block scalars extend to the next peer field, cookies retain spaces/semicolons, only whole-value [REDACTED] and unquoted Java object references under token are excluded, URL user:password@ after :// and MySQL @tcp(/@unix( need no keyword, curl -u or --user user:password arguments report the password (or the username when the password is empty), and a 40-byte secret using ASCII letters, digits, + or / is accepted within 128 bytes of an AKIA, ASIA, ABIA or ACCA access-key ID (NewScanner default: on).
	KindCredential Kind = "credential"
	// KindPAN finds 13–19 digits with Visa, Mastercard, Amex, JCB, Discover, Diners or UnionPay prefixes; Luhn plus issuer length scores 1.0, a failed checksum 0.6, and an attached business label 0.4. No keyword is needed; spaces/hyphens are allowed, prefixes are 4, 51–55 or 2221–2720, 34/37, 3528–3589, 6011/644–649/65, 300–305/36/38 and 62 respectively, with Luhn-valid lengths 13/16, 16, 15, 16, 16, 14–16 and 16–19; other Luhn-valid lengths are rejected (NewScanner default: on).
	KindPAN Kind = "pan"
	// KindEmail extracts ASCII local parts using letters, digits and .+-_ before @ and dotted domains using letters, digits and .-; structure checks score 0.7 or 0.8 for an unknown TLD and 0.9 or 1.0 for a known TLD. Without a keyword, require a nonempty local part without edge/consecutive dots, no leading domain dot or hyphen at label edges, and an alphabetic TLD of at least 2 letters; consecutive domain dots select the lower score, trailing dots/hyphens are trimmed, and known TLDs are com/org/net/edu/gov/mil/int/io/co/us/uk/de/fr/jp/cn/kr/au/ca/info/biz/name/pro/museum/coop/aero (case-insensitive) (NewScanner default: on).
	KindEmail Kind = "email"
	// KindJPPhone recognizes 10- or 11-digit Japanese numbers beginning with 0, allowing spaces, hyphens and parentheses; prefix/length checks score landlines 0.8, other accepted types 0.9, and business labels 0.4. No keyword is needed; 11-digit prefixes are 090/080/070/050/020/060/0800, 0120 takes 10 digits, and other 10-digit landlines start 01–09 but exclude 020/021/050/051/057/060/070/071/080/081/090/091 (NewScanner default: on).
	KindJPPhone Kind = "phone_jp"
	// KindUSPhone recognizes separated ten-digit North American numbers such as (202) 555-0123, 202-555-0123, 202.555.0123 or 202 555 0123, with an optional +1 or 1 country code; area and exchange codes are checked against the numbering plan (area 2–9 then 0–8, exchange 2–9 and not N11) and the two separators must match, so unseparated IDs and timestamps stay visible. Scores are 0.7, 0.9 after a phone, tel, mobile, cell, fax, call or contact label, and 0.4 after a business label (NewScanner default: on).
	KindUSPhone Kind = "phone_us"
	// KindMyNumber recognizes 12 digits with optional spaces or hyphens as Japanese individual-number candidates; the weighted MOD 11 check gives 0.95, or 0.4 under a business label, without requiring a keyword; only a contiguous 12-digit account field of a syntactic ARN with an AWS partition is excluded. Weights on the first 11 digits from right to left are 2,3,4,5,6,7,2,3,4,5,6; a remainder of 0 or 1 requires check digit 0, otherwise 11 minus the remainder (NewScanner default: on).
	KindMyNumber Kind = "mynumber"
	// KindJWT parses eyJ-prefixed base64url text with exactly two dots and nonempty header and payload segments; header checks yield 0.5, 0.7 or 0.8 with an empty signature, and 0.7, 0.9 or 1.0 otherwise. Those tiers mean undecodable/non-object header, decoded JSON object without alg, and object with alg of any type; no context keyword, signature verification or payload JSON validation is required (NewScanner default: on).
	KindJWT Kind = "jwt"
	// KindAWSKey identifies AKIA (long-term), ASIA (temporary), ABIA (STS service bearer) or ACCA (context-specific) followed by exactly 16 uppercase ASCII letters or digits (20 characters total); length, alphabet and alphanumeric boundary checks give 0.95 without a context keyword or authentication (NewScanner default: on).
	KindAWSKey Kind = "awskey"
	// KindIBAN accepts two ASCII country letters, two digits and an alphanumeric BBAN with optional internal spaces; country length and MOD 97 checks give 0.95, rejecting check digits 00, 01 and 99 without requiring a keyword. Case is ignored; registry lengths are 15:NO; 16:BE; 18:DK/FI/FK/FO/GL/NL/SD; 19:MK/SI; 20:AT/BA/EE/KZ/LT/LU/MN/XK; 21:CH/HR/LI/LV; 22:BG/BH/CR/DE/GB/GE/IE/ME/RS/VA; 23:AE/GI/IL/IQ/OM/SO/TL; 24:AD/CZ/ES/MD/PK/RO/SA/SE/SK/TN/VG; 25:LY/PT/ST; 26:IS/TR; 27:BI/DJ/FR/GR/IT/MC/MR/SM; 28:AL/AZ/BY/CY/DO/GT/HN/HU/LB/NI/PL/SV; 29:BR/EG/PS/QA/UA; 30:JO/KW/MU/YE; 31:MT/SC; 32:LC; 33:RU (NewScanner default: on).
	KindIBAN Kind = "iban"
	// KindIPAddr extracts dotted IPv4 decimal octets and colon-separated IPv6 hexadecimal text, including :: shorthand; net.ParseIP validation gives 0.8, excluding unspecified and loopback addresses with no keyword needed. IPv4 requires 4 octets in 0–255 and token boundaries; IPv6 includes trailing dotted quads (mapped, compatible and NAT64 forms); attached version, v, ver, build or release labels exclude IPv4 candidates (NewScanner default: on).
	KindIPAddr Kind = "ipaddr"
	// KindSWIFTBIC accepts 8 or 11 ASCII alphanumerics as four bank letters, two country letters, location and optional branch; country and structure checks give 0.85, with case ignored and no institution lookup. The location has 2 characters and the branch 3; all-letter candidates require swift, bic, bank identifier or wire within 50 bytes as case-insensitive whole words; a preceding swift accepts separator-insensitive code, no, number, address and bic labels, digit-bearing candidates need no keyword, syscall hex register slots, invalid-user slots, underscore identifiers and hardware wire warnings are excluded, and path components are excluded except contextual slash-separated code lists (NewScanner default: on).
	KindSWIFTBIC Kind = "swiftbic"
	// KindABARouting selects 9 consecutive digits beginning 01–12, 21–32, 61–72 or 80 as US routing candidates; the repeating 3,7,1 weighted MOD 10 checksum must pass, giving 0.85 without a keyword. Decimal fragments and values assigned to eventtime, downtime, lock or ino are excluded Exception counters followed by double-hummer alignment exceptions and log.<number> sequence suffixes are excluded (NewScanner default: on).
	KindABARouting Kind = "aba_routing"
	// KindUKSortCode picks six digits in three pairs separated consistently by hyphens or spaces with matching separators, excluding all-zero codes; structure checks give 0.7, or 0.55 for contextual date-like candidates, without a checksum. When the middle pair is 01–12 and either outer pair is 01–31, sort code, sort-code, sortcode, sort_code, sc: or bacs must occur within 40 bytes (case-insensitive substring); other candidates need no keyword (NewScanner default: on).
	KindUKSortCode Kind = "uk_sortcode"
	// KindCVV finds 3 or 4 consecutive digits within 30 bytes of a verification-code keyword end; length and non-overlap checks yield 0.85 without a checksum. The required keywords are cvv, cvc, cid, cvv2, cvc2, security code or セキュリティコード, with ASCII case ignored (NewScanner default: on).
	KindCVV Kind = "cvv"
	// KindCardExpiry reads MM/YY, MM/YYYY, MM-YY or MM-YYYY near expiration labels; month 01–12 and adjacent-digit checks yield 0.85, without checking whether the date is in the future. Search starts within 50 bytes before or after the required case-insensitive keyword exp, exp date, expiry, expires, expiration, expiration date, valid thru, valid through or 有効期限 (NewScanner default: on).
	KindCardExpiry Kind = "card_expiry"
	// KindPaymentToken covers Stripe identifiers and keys, PayPal PAYID- and Square sq0idp-/sq0csp- tokens; prefix and minimum-body checks yield 0.9 with no keyword or authentication. Bodies use ASCII letters, digits, _ or -; sk_live_, pk_live_, sk_test_, pk_test_, PAYID-, sq0idp- and sq0csp- require at least 16 body bytes, while tok_, pi_, pm_, cus_, sub_, price_ and prod_ require 8 (NewScanner default: on).
	KindPaymentToken Kind = "payment_token"
	// KindBankAccount looks for 4–17 consecutive digits within 50 bytes of a banking keyword end; length checks give 0.5, raised to 0.65 by nearby holder context, without a checksum. Required keywords are 口座番号, 口座名義, 振込先, 銀行口座, 預金口座, bank account, account number, acct no or account no (ASCII case-insensitive); the boost needs 名義, 名義人, holder, Holder, beneficiary or Beneficiary within 50 bytes of the digits, with those spellings matched literally (NewScanner default: on).
	KindBankAccount Kind = "bank_account"
	// KindACHTrace takes 15 consecutive digits within 50 bytes of an ACH or trace keyword end; prefix validation requires 01–12, 21–32, 61–72 or 80 and scores 0.75 without a checksum. Context is mandatory: ach, ach trace, trace number, trace no, trace # or trace# with ASCII case ignored (NewScanner default: on).
	KindACHTrace Kind = "ach_trace"
	// KindMerchantID finds 15 ASCII alphanumerics for merchant IDs or 8 consecutive digits at alphanumeric boundaries for terminal IDs; length and keyword-overlap checks give 0.7 without checksum validation. A keyword must end within 30 bytes of the candidate: merchant id, MID: or MID followed by a space, 加盟店ID or 加盟店 for merchants; terminal id, TID: or TID followed by a space, 端末ID or 端末 for terminals, with ASCII case ignored (NewScanner default: on).
	KindMerchantID Kind = "merchant_id"
	// KindBTC recognizes mainnet 1/3 Base58 text of 25–34 characters or single-case bc1 text of 42 or 62 characters; Base58Check or Bech32/Bech32m checksum validation gives 0.95 without a keyword. Legacy decoding must produce 25 bytes with version 0 or 5 and a double-SHA-256 check; bc1 requires the Bech32 alphabet and version 0 with Bech32 or versions 1–16 with Bech32m, but does not decode witness-program padding (NewScanner default: on).
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
	// KindChinaResidentID requires 17 digits followed by a digit or uppercase X, including a YYYYMMDD birth date; province, date, sequence and MOD 11-2 checks yield 0.95, or 0.4 under a business label, with no keyword. The first two digits must be 11–15, 21–23, 31–37, 41–46, 50–54, 61–65, 71, 81 or 82; the date at positions 7–14 must exist in year 0001–9999 and positions 15–17 cannot be 000, but district assignment is not checked (NewScanner default: off).
	KindChinaResidentID Kind = "cn_resident_id"
	// KindKoreaRRN reads 13 digits, contiguous or hyphenated 6-7, with a birth date and century/sex digit; the legacy weighted MOD 11 check scores 0.95, labeled check failures 0.6, and business labels 0.4. Digit 7 must be 9/0 for the 1800s, 1/2 for the 1900s or 3/4 for the 2000s; after date validation, checksum failure requires an immediately preceding rrn (case-insensitive) or 주민등록번호 label within 48 bytes in the same field, whereas a passing checksum needs no keyword (NewScanner default: off).
	KindKoreaRRN Kind = "kr_rrn"
	// KindCanadaSIN finds 9 digits starting with 1–7 or 9, contiguous or hyphenated 3-3-3; Luhn checksum validation yields 0.95, or 0.4 under a business label, without a keyword. Repeated single-digit values are excluded (NewScanner default: off).
	KindCanadaSIN Kind = "ca_sin"
)
