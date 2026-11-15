# Detect forgotten credentials

Use `KindCredential` for assignments and connection strings, `KindServiceToken` for documented provider prefixes, and `KindHighEntropy` for uncertain unlabelled tokens. NewScanner includes all three. Findings contain only byte spans, kind and heuristic confidence; scanning never authenticates with a provider. Use public fictitious inputs in tests.

Credential assignments recognize the sensitive-key rule with ASCII case and `_`, `-`, `.`, or space variants: password, passwd, secret, token, api_key, authorization, cookie and set-cookie. The detector accepts `=`, `:`, quoted JSON fields and header forms. Quotes honor backslash escapes. Unquoted values end at field delimiters; cookie headers extend to the end of the line. Authorization retains Bearer or Basic and hides the credential. Arbitrary programming-language expressions, concatenated runtime values and recursive encodings are outside this parser.

URL userinfo and postgres, mysql, mongodb, redis and amqp URI passwords preserve the username, host and database. Go MySQL's `user:password@tcp(host)/database` and `@unix(...)` forms are supported. Percent-encoded delimiters remain part of the secret span. Credential grammar deliberately uses original bytes, so a fully percent-encoded field name or delimiter is not decoded by this detector. This differs from the older built-ins' one-layer percent decoding.

Provider secret fields include X-Amz-Signature, sig, AccountKey, SharedAccessSignature, aws_secret_access_key, SecretAccessKey, private_key, client_secret, TWILIO_AUTH_TOKEN and auth_token. These are contextual candidates, not account existence checks. An unlabelled 40-byte base64 AWS secret within 128 bytes of an access-key ID is also detected. Azure storage and Twilio secrets have no unique secret prefix; their public IDs alone are not misrepresented as secret-key detection. Ordinary `sig` fields can be false positives. PEM detection includes the full body through a matching END marker; incomplete inputs identify only their header.

| Family | Public format evidence | Implemented boundary |
|---|---|---|
| OpenAI | [API authentication](https://developers.openai.com/api/reference/overview), [project API keys](https://platform.openai.com/docs/api-reference/project-api-keys) | sk-proj- and sk-svcacct-, at least 16 token characters |
| Anthropic | [API examples](https://docs.anthropic.com/en/docs/agents-and-tools/claude-for-sheets) | sk-ant-api03- and sk-ant-admin01-, at least 16 characters |
| Stripe | [API keys](https://docs.stripe.com/keys), [webhook signatures](https://docs.stripe.com/webhooks/signature) | sk_live_, rk_live_, whsec_; public pk_live_ is excluded |
| GitHub | [Token formats](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) | Existing classic and github_pat_ detector retained |
| GitLab | [Token prefixes](https://docs.gitlab.com/security/tokens/) | glpat-; self-managed custom prefixes need a custom detector |
| npm | [Public token format](https://github.blog/security/announcing-npms-new-access-token-format/) | npm_ |
| PyPI | [Token internals](https://docs.pypi.org/trusted-publishers/internals/) | pypi- |
| Slack | [Incoming webhook URLs](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) | Three path segments under hooks.slack.com or hooks.slack-gov.com; hide the path credential |
| SendGrid | [Public format example](https://www.twilio.com/en-us/blog/developers/community/build-a-sendgrid-mcp-server-for-ai-email-workflows) | SG. followed by 22 and 43 URL-safe characters |
| Google OAuth | [OAuth client-secret example](https://codelabs.developers.google.com/generate_creatives_google_ads) | GOCSPX- |
| Google service accounts | [Service-account keys](https://cloud.google.com/iam/docs/keys-create-delete) | private_key assignment and complete PEM body |
| Azure | [Connection strings](https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string) | AccountKey and SAS sig fields; other query parameters remain readable |
| AWS | [Access-key pairs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html), [query authentication](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html) | Secret fields, nearby 40-byte secret and X-Amz-Signature |
| Twilio | [API key resource](https://www.twilio.com/docs/iam/api-keys/resource-v2010), [Auth Token](https://www.twilio.com/docs/iam/api/authtoken) | Secret/auth_token assignments; SK identifies a key, not its secret |

The general minimum suffix length is a conservative detector heuristic, not a vendor specification. Prefix matching does not validate token checksums or revocation. Formats can evolve; public examples are the evidence, and local synthetic tests never use real keys.

HighEntropy requires 32–256 base64-like characters, at least three character classes and Shannon entropy of at least 4.5 bits per byte. It reports confidence 0.3. Hex hashes, typical UUIDs and directly labelled IDs are excluded. A public random ID without its label is indistinguishable from a secret with the same character distribution; see the measured false positives in [accuracy](accuracy.md).

Scanner, slog, adapters and embargotest keep the existing threshold 0 contract. Slog and adapters receive an explicit Scanner, so changing its threshold behind the caller's back would discard their chosen findings. embargotest keeps low-confidence checks to favor finding forgotten values. Users who want fewer ambiguous candidates can pass `WithMinConfidence(0.5)` explicitly, accepting the documented entropy recall loss. Confidence is not probability, and a clean result proves only the tested canary, detector set and observed paths.

Error values are checked using their full Error text after wrapping or joining. A MaskError wrapper was deliberately not added: an Unwrap method would let Sentry or another chain-walking consumer recover the original unsanitized message, while removing Unwrap would break errors.Is/errors.As. At an external text-only boundary, use `embargo.Mask(err.Error(), scanner.ScanString(err.Error()))` and retain the original error for local identity checks. For SDK events, inspect or sanitize the complete serialized event, including each exception, resource and context.

[Support maintenance](https://github.com/sponsors/nao1215).
