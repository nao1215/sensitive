# Supported detectors


| Kind | Detects | Validation |
|--------|---------|------------|
| `KindPAN` | Credit card candidates (Visa, Mastercard, Amex, JCB, Discover, Diners, UnionPay) | BIN prefix + Luhn; checksum failures remain lower-confidence candidates |
| `KindEmail` | Email addresses | Structure + known TLD check |
| `KindJPPhone` | Japanese phone numbers (mobile, landline, IP phone, toll-free, M2M/IoT, service) | Prefix classification + digit count |
| `KindMyNumber` | Japanese My Number (12-digit individual number) | MOD 11 check digit |
| `KindJWT` | JSON Web Tokens | Header decode + `alg` key check |
| `KindAWSKey` | AWS Access Key IDs (`AKIA...` / `ASIA...`) | Prefix + 20-char alphanumeric |
| `KindIBAN` | International Bank Account Numbers | Country code + MOD 97 check digit |
| `KindIPAddr` | IPv4 and IPv6 addresses | `net.ParseIP` + octet range |
| `KindSWIFTBIC` | SWIFT/BIC codes | Format + country code validation; all-letter codes such as DEUTDEFF also need nearby swift, bic, bank identifier or wire text |
| `KindABARouting` | US ABA routing numbers | Prefix range + checksum |
| `KindUKSortCode` | UK sort codes (XX-XX-XX) | Pattern + boundary checks |
| `KindCVV` | Card verification values (CVV/CVC/CID) | Context keyword + digit length (context-based, weaker) |
| `KindCardExpiry` | Card expiration dates | Context keyword + MM/YY validation (context-based, weaker) |
| `KindPaymentToken` | Payment processor tokens (Stripe/PayPal/Square) | Prefix + minimum body length |
| `KindBankAccount` | Bank account numbers (context-based) | Context keyword + digit range (context-based, weaker) |
| `KindACHTrace` | ACH trace numbers | Context keyword + prefix range (context-based, weaker) |
| `KindMerchantID` | Merchant/terminal IDs | Context keyword + format (context-based, weaker) |
| `KindBTC` | Bitcoin addresses (P2PKH, P2SH, Bech32, Bech32m/Taproot) | Base58Check (double SHA-256) / Bech32 polynomial checksum |
| `KindETH` | Ethereum addresses (0x + 40 hex) | EIP-55 for mixed case; uniform case requires no checksum |
| `KindGitHubToken` | GitHub tokens (classic `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, fine-grained `github_pat_`) | Prefix + body character set + length |
| `KindSlackToken` | Slack API tokens (`xoxb-`/`xoxp-`/`xoxa-`/`xoxo-`/`xoxr-`/`xoxs-`) | Prefix + type character + minimum body length |
| `KindGoogleAPIKey` | Google API keys (`AIza...`) | Prefix + 35-char body |
| `KindPrivateKeyPEM` | PEM private key headers (RSA/EC/DSA/OpenSSH/PKCS#8) | `-----BEGIN [ALGO ]PRIVATE KEY-----` header parse |
| `WithAll()` | All of the above | |


Validation checks format, not account existence or credential authentication. Confidence scores are heuristics, not probabilities. See the [accuracy corpus](accuracy.md) for examples of misses and false alarms.

[Support maintenance](https://github.com/sponsors/nao1215).
