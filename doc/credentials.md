# Detect forgotten credentials

Use `KindCredential` for assignments and connection strings, `KindServiceToken` for documented provider prefixes, and `KindHighEntropy` for uncertain unlabeled tokens. `NewScanner` includes credential and service-token detection by default. Add `WithAll()` or select `KindHighEntropy` with `WithKinds` to scan unlabeled random-looking tokens. Findings contain only byte spans, kind and heuristic confidence; scanning never authenticates with a provider. Use public fictitious inputs in tests.

[KindCredential](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCredential) lists the accepted keys, delimiter grammar, URL/DSN forms and AWS proximity rule. Arbitrary programming-language expressions, concatenated runtime values and recursive encodings are outside this parser. A field named `sig` can be a public application signature, and cloud account IDs alone do not establish that a secret is present.

The parser consumes original bytes so percent-encoded delimiters remain part of URL secrets. A fully encoded field name or delimiter can therefore be missed. [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) defines provider-prefix and body constraints; the sources below explain the formats behind those choices.

| Family | Public format evidence | Matching contract |
|---|---|---|
| OpenAI | [OpenAI project-key example](https://github.com/openai/codex-action/blob/main/examples/test-sandbox-protections.yml), [public service-key format documentation](https://github.com/mongodb/kingfisher/blob/main/docs/BLAST_RADIUS.md#openai-openai) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) |
| Anthropic | [API examples](https://platform.claude.com/docs/en/manage-claude/compliance-api-access) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) |
| Stripe | [API keys](https://docs.stripe.com/keys), [webhook signatures](https://docs.stripe.com/webhooks/signature) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) |
| GitHub | [Token formats](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) | [KindGitHubToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindGitHubToken) |
| GitLab | [Token prefixes](https://docs.gitlab.com/security/tokens/) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) |
| npm | [Public token format](https://github.blog/security/announcing-npms-new-access-token-format/) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) |
| PyPI | [Token internals](https://docs.pypi.org/trusted-publishers/internals/) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) |
| Slack | [Incoming webhook URLs](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) |
| SendGrid | [Public format example](https://www.twilio.com/en-us/blog/developers/community/build-a-sendgrid-mcp-server-for-ai-email-workflows) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) |
| Google OAuth | [OAuth client-secret example](https://codelabs.developers.google.com/generate_creatives_google_ads) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken) |
| Google service accounts | [Service-account keys](https://cloud.google.com/iam/docs/keys-create-delete) | [KindPrivateKeyPEM](https://pkg.go.dev/github.com/nao1215/embargo@main#KindPrivateKeyPEM) |
| Azure | [Connection strings](https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string) | [KindCredential](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCredential) |
| AWS | [Access-key pairs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html), [query authentication](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html) | [KindCredential](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCredential) |
| Twilio | [API key resource](https://www.twilio.com/docs/iam/api-keys/resource-v2010), [Auth Token](https://www.twilio.com/docs/iam/api/authtoken) | [KindCredential](https://pkg.go.dev/github.com/nao1215/embargo@main#KindCredential) |

The general minimum suffix length is a conservative detector heuristic, not a vendor specification. Prefix matching does not validate token checksums or revocation. Formats can evolve; public examples are the evidence, and local synthetic tests never use real keys.

[KindHighEntropy](https://pkg.go.dev/github.com/nao1215/embargo@main#KindHighEntropy) defines the opt-in statistical heuristic and its exclusions. A public random ID without its label is indistinguishable from a secret with the same character distribution; see the measured false positives in [accuracy](accuracy.md).

Scanner, slog, adapters and embargotest keep the existing threshold 0 contract. Slog and adapters receive an explicit Scanner, so changing its threshold behind the caller's back would discard their chosen findings. embargotest keeps low-confidence checks to favor finding forgotten values. Users who want fewer ambiguous candidates can pass `WithMinConfidence(0.5)` explicitly, accepting the documented entropy recall loss. Confidence is not probability, and a clean result proves only the tested canary, detector set and observed paths.

Error values are checked using their full Error text after wrapping or joining. A MaskError wrapper was deliberately not added: an Unwrap method would let Sentry or another chain-walking consumer recover the original unsanitized message, while removing Unwrap would break errors.Is/errors.As. At an external text-only boundary, use `embargo.Mask(err.Error(), scanner.ScanString(err.Error()))` and retain the original error for local identity checks. For SDK events, inspect or sanitize the complete serialized event, including each exception, resource and context.

[Support maintenance](https://github.com/sponsors/nao1215).
