# Supported detectors

The [Kind godoc](https://pkg.go.dev/github.com/nao1215/embargo@main#Kind) defines what each detector matches, how it is checked, the confidence it emits and its default selection; [Rules by kind](#rules-by-kind) lists the prefixes, keywords and exclusions of the longer entries. The [README table](../README.md#find-and-mask-sensitive-text) is generated from those comments. Use this page to interpret findings and choose a threshold; format acceptance does not establish account ownership, identity issuance or successful authentication.

## Confidence and false positives

Confidence ranks evidence used by a detector, not the probability that a value is secret. A checksum protects against many transcription errors but says nothing about why a number appears in a log. A structurally valid public order number can share every digit with a personal identifier. The scanner keeps such ambiguous matches so callers can choose the cost of missed secrets versus excess masking.

| Situation | Why interpretation matters | Matching contract |
|---|---|---|
| `order_id=4111111111111111` | A public order ID can look exactly like a payment card | [KindPAN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPAN) |
| `sort code: 20-12-25` | The same text can denote a date or a bank branch | [KindUKSortCode](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUKSortCode) |
| `bank account 12345678 holder John` | A nearby name strengthens context but does not confirm an account | [KindBankAccount](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBankAccount) |
| `alice@ex..ample.com` | Address-shaped text can deserve masking even when mail delivery would fail | [KindEmail](https://pkg.go.dev/github.com/nao1215/embargo@main#KindEmail) |
| `swift DEUTDEFF` | Context distinguishes an all-letter bank code from an ordinary word | [KindSWIFTBIC](https://pkg.go.dev/github.com/nao1215/embargo@main#KindSWIFTBIC) |
| A public random request identifier | Removing its label can make it indistinguishable from an opaque secret | [KindHighEntropy](https://pkg.go.dev/github.com/nao1215/embargo@main#KindHighEntropy) |

The numeric tiers live in godoc, where they are tested against representative scans. [PAN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPAN) retains checksum failures, [JWT](https://pkg.go.dev/github.com/nao1215/embargo@main#KindJWT) distinguishes header evidence from signature presence, and [ETH](https://pkg.go.dev/github.com/nao1215/embargo@main#KindETH) treats uniform and mixed case differently. A single threshold therefore has different effects across families; the [exact-span accuracy measurements](accuracy.md) and [country evaluation](countries.md) show those tradeoffs on fixed data.

## Parser boundaries

A [Japanese telephone](https://pkg.go.dev/github.com/nao1215/embargo@main#KindJPPhone) match does not consult a complete area-code allocation database. A [Chinese resident ID](https://pkg.go.dev/github.com/nao1215/embargo@main#KindChinaResidentID) can pass its checks even when its district/date combination could never have been issued. Modern [Korean RRN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindKoreaRRN) loses the evidence supplied by legacy check digits; an unlabeled value can be missed. The [country sources and evaluation](countries.md#definitions-and-independent-checks) explain why those limits affect detector selection.

[Bitcoin](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBTC) acceptance is not a full wallet-address validator: a checksummed witness string can pass without proving canonical witness-program padding. [PEM](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPrivateKeyPEM) acceptance does not prove that a key body is parseable or cryptographically sound. Use a protocol library when those stronger guarantees are required after detection.

Numeric parsers reject decimal tails, some hostname fragments and groups inside canonical 8-4-4-4-12 UUIDs so operational log fields do not become isolated identifiers. Boundaries differ by family: contextual digit searches can find a digit run beside letters, while country parsers exclude adjacent ASCII identifier characters. [Scan](https://pkg.go.dev/github.com/nao1215/embargo@main#Scanner.Scan) documents decoding and byte offsets; [Kind](https://pkg.go.dev/github.com/nao1215/embargo@main#Kind) documents normalization and business-label scope. The [adversarial encoding regressions](testing.md#adversarial-budgets) retain examples of unsupported disguises.

[Credential grammar and provider sources](credentials.md) explain the evidence behind secret detection. Prefixes alone do not check revocation, and the generic credential parser cannot evaluate programming-language expressions or reconstruct values assembled at runtime. The [real-log analysis](real-logs.md) records observed false positives without claiming recall for unknown production secrets.

## Rules by kind

The Kind godoc states what each detector matches, how it is checked and its scores. The rules below complete the longer entries: prefix and keyword lists, exclusions and accepted layouts.

Rules shared by several kinds: a business label means order, invoice, tracking, version, build, serial or shipment immediately before a candidate in the same field, within 48 bytes, optionally followed by id, number, ref or code; ASCII case is ignored. Numeric normalization accepts full-width digits and Unicode dash variants for PAN, JPPhone, MyNumber, ABARouting, BankAccount and the eleven country kinds. Built-ins except Credential ignore interior non-ASCII Unicode Pd, Zs, Cf and Sm intersected with Dash in token runs, while ASCII space and hyphen remain delimiters; U+30FC remains a legacy numeric hyphen, and [the normalization policy](policies.md) has the allow list. Scan decodes one percent-encoding layer for every built-in except Credential.

### KindServiceToken

ASCII letters, digits, _ and - form bodies of at least 16 bytes after sk-proj-, sk-svcacct-, sk-ant-api03-, sk-ant-admin01-, sk-admin-, sk_live_, rk_live_, whsec_, glpat-, npm_, pypi- or GOCSPX-, and GitLab glcbt-, gldt-, glffct-, glft-, glimt-, glrt-, glsoat-, glagent-, gloas- and GR1348941 bodies of at least 20 bytes may end in dot-separated routing parts; SG. requires 22 and 43 such bytes separated by a dot or 66 bytes that may include = and dots. About 70 further layouts (DigitalOcean, Shopify, HashiCorp Vault and Terraform, Databricks, Doppler, Dynatrace, Postman, Pulumi, Sentry, Grafana, Hugging Face, New Relic, Twilio API keys, Microsoft Entra client secrets, Telegram bots, MaxMind, Mailchimp, Facebook app tokens and others) fix the body alphabet and length per prefix as listed at https://github.com/nao1215/embargo/blob/main/doc/credentials.md; a body made of one repeated byte, such as xxxx, is a placeholder and is not reported. Slack https://hooks.slack.com/ or hooks.slack-gov.com URLs (http, https or no scheme) report the path after services/ (three parts), workflows/ or triggers/ (three or four parts) when parts have at least 2 bytes and the last at least 16, and Microsoft Teams *.webhook.office.com/webhookb2/ URLs report the path containing /IncomingWebhook/.

### KindHighEntropy

No keyword is required; slash/backslash-adjacent or dotted path components and assignments to id, requestid, traceid, spanid, commit, sha, hash, checksum or uuid (case and key separators ignored) and lowercase Kubernetes generated names ending in a five-character random suffix are excluded.

### KindCredential

Required assignment keys are password, passwd, secret, token, api_key, authorization, proxy-authorization, cookie, set-cookie, access_token, refresh_token, id_token, x-api-key, DB_PASSWORD, Private-Token, PGPASSWORD, X-Amz-Signature, sig, AccountKey, SharedAccessSignature, aws_secret_access_key, SecretAccessKey, private_key, client_secret, TWILIO_AUTH_TOKEN or auth_token, plus keys whose final separator/camel-case segment is password, passwd, secret, token, credential or auth, or key preceded by api, secret, private, access or account (ASCII case and _, -, dot or space variants, optionally followed by a number such as api_token_2); =, :, :=, ::=, :::=, ?=, +=, ||=, spaced .= or => introduces the value, a Go string or []byte type between the key and = and a string type annotation (name: String = value) are skipped, PHP print_r [key] => value is accepted, XML elements named by a key (including a namespace prefix) report their trimmed text content when the matching closing tag follows, Go/JSON quote, hexadecimal/Unicode quote and backslash escapes are scanned through four string layers with original offsets, quoted Bearer/Basic values need no key, fmt map/slice and Go typed literal values include all elements without decoding byte lists, unquoted values stop at field delimiters, fmt fields retain spaces until the next field, indented YAML block scalars extend to the next peer field, cookies retain spaces/semicolons, only whole-value [REDACTED], unquoted Java object references under token and canonical UUID values of clientToken or idempotencyToken are excluded, URL user:password@ after :// and MySQL @tcp(/@unix( need no keyword, curl -u or --user user:password arguments report the password (or the username when the password is empty), and a 40-byte secret using ASCII letters, digits, + or / is accepted within 128 bytes of an AKIA, ASIA, ABIA or ACCA access-key ID.

### KindPAN

No keyword is needed; spaces/hyphens are allowed, prefixes are 4, 51–55 or 2221–2720, 34/37, 3528–3589, 6011/644–649/65, 300–305/36/38 and 62 respectively, with Luhn-valid lengths 13/16, 16, 15, 16, 16, 14–16 and 16–19; other Luhn-valid lengths are rejected.

### KindEmail

Without a keyword, require a nonempty local part without edge/consecutive dots, no leading domain dot or hyphen at label edges, and an alphabetic TLD of at least 2 letters; consecutive domain dots select the lower score, trailing dots/hyphens are trimmed, and known TLDs are com/org/net/edu/gov/mil/int/io/co/us/uk/de/fr/jp/cn/kr/au/ca/info/biz/name/pro/museum/coop/aero (case-insensitive).

### KindJPPhone

No keyword is needed; 11-digit prefixes are 090/080/070/050/020/060/0800, 0120 takes 10 digits, and other 10-digit landlines start 01–09 but exclude 020/021/050/051/057/060/070/071/080/081/090/091.

### KindUSPhone

The forms are (202) 555-0123, 202-555-0123, 202.555.0123 or 202 555 0123. Area codes start 2–9 with a second digit 0–8; exchange codes start 2–9 and are not N11. The two separators must match, so unseparated IDs and timestamps stay visible.

### KindMyNumber

Weights on the first 11 digits from right to left are 2,3,4,5,6,7,2,3,4,5,6; a remainder of 0 or 1 requires check digit 0, otherwise 11 minus the remainder.

### KindJWT

Those tiers mean undecodable/non-object header, decoded JSON object without alg, and object with alg of any type; no context keyword, signature verification or payload JSON validation is required.

### KindIBAN

Case is ignored; registry lengths are 15:NO; 16:BE; 18:DK/FI/FK/FO/GL/NL/SD; 19:MK/SI; 20:AT/BA/EE/KZ/LT/LU/MN/XK; 21:CH/HR/LI/LV; 22:BG/BH/CR/DE/GB/GE/IE/ME/RS/VA; 23:AE/GI/IL/IQ/OM/SO/TL; 24:AD/CZ/ES/MD/PK/RO/SA/SE/SK/TN/VG; 25:LY/PT/ST; 26:IS/TR; 27:BI/DJ/FR/GR/IT/MC/MR/SM; 28:AL/AZ/BY/CY/DO/GT/HN/HU/LB/NI/PL/SV; 29:BR/EG/PS/QA/UA; 30:JO/KW/MU/YE; 31:MT/SC; 32:LC; 33:RU.

### KindIPAddr

IPv4 requires 4 octets in 0–255 and token boundaries; IPv6 includes trailing dotted quads (mapped, compatible and NAT64 forms); attached version, v, ver, build or release labels exclude IPv4 candidates.

### KindSWIFTBIC

The location has 2 characters and the branch 3; all-letter candidates require swift, bic, bank identifier or wire within 50 bytes as case-insensitive whole words; a preceding swift accepts separator-insensitive code, no, number, address and bic labels, digit-bearing candidates need no keyword, syscall hex register slots, invalid-user slots, underscore identifiers and hardware wire warnings are excluded, and path components are excluded except contextual slash-separated code lists.

### KindABARouting

Decimal fragments and values assigned to eventtime, downtime, lock or ino are excluded, as are exception counters followed by the kernel phrase double-hummer alignment exceptions and log.<number> sequence suffixes.

### KindUKSortCode

When the middle pair is 01–12 and either outer pair is 01–31, sort code, sort-code, sortcode, sort_code, sc: or bacs must occur within 40 bytes (case-insensitive substring); other candidates need no keyword.

### KindPaymentToken

Bodies use ASCII letters, digits, _ or -; sk_live_, pk_live_, sk_test_, pk_test_, PAYID-, sq0idp- and sq0csp- require at least 16 body bytes, while tok_, pi_, pm_, cus_, sub_, price_ and prod_ require 8.

### KindBankAccount

Required keywords are 口座番号, 口座名義, 振込先, 銀行口座, 預金口座, bank account, account number, acct no or account no (ASCII case-insensitive); the boost needs 名義, 名義人, holder, Holder, beneficiary or Beneficiary within 50 bytes of the digits, with those spellings matched literally.

### KindMerchantID

A keyword must end within 30 bytes of the candidate: merchant id, MID: or MID followed by a space, 加盟店ID or 加盟店 for merchants; terminal id, TID: or TID followed by a space, 端末ID or 端末 for terminals, with ASCII case ignored.

### KindBTC

Legacy decoding must produce 25 bytes with version 0 or 5 and a double-SHA-256 check; bc1 requires the Bech32 alphabet and version 0 with Bech32 or versions 1–16 with Bech32m, but does not decode witness-program padding.

### KindChinaResidentID

The first two digits must be 11–15, 21–23, 31–37, 41–46, 50–54, 61–65, 71, 81 or 82; the date at positions 7–14 must exist in year 0001–9999 and positions 15–17 cannot be 000, but district assignment is not checked.

### KindKoreaRRN

Digit 7 must be 9/0 for the 1800s, 1/2 for the 1900s or 3/4 for the 2000s; after date validation, checksum failure requires an immediately preceding rrn (case-insensitive) or 주민등록번호 label within 48 bytes in the same field, whereas a passing checksum needs no keyword.

## Updating detector documentation

Edit the individual constant comment in finding.go, and the matching entry under Rules by kind when the detail changes, then run `go -C tests run ./cmd/detectordocs`. Each comment separates matching from validation with its first semicolon and ends with the NewScanner default in parentheses. The generator uses go/ast, takes the first validation sentence and shortens cells at word boundaries to the prose checker's 120-character budget; each Kind links to its full godoc.

`go -C tests run ./cmd/detectordocs --check` rejects stale output. `go -C tests test ./cmd/detectordocs` checks all constants, validation clauses, README membership, exact regeneration, observed confidence tiers and default detection through `NewScanner()`. Both commands run in CI; a new kind needs representative inputs for each score before its documentation can pass.

[Support maintenance](https://github.com/sponsors/nao1215).
