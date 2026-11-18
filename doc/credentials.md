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
| About 70 further providers | [gitleaks v8.30.0 default rules](https://github.com/gitleaks/gitleaks/tree/v8.30.0/cmd/generate/config/rules) | [KindServiceToken](https://pkg.go.dev/github.com/nao1215/embargo@main#KindServiceToken), layouts below |

The layouts below follow the gitleaks rules named in the table, without the keyword that many gitleaks rules require, so each prefix must be distinctive on its own. Hex means 0-9 and a-f; alnum means ASCII letters and digits; token bytes add _ and -; base64 adds + and / and allows trailing = padding. A body made of one repeated byte is treated as a placeholder.

| Provider | Layout |
|---|---|
| 1Password | ops_eyJ + 250 or more base64; A3- + upper-case alnum groups 6-11-5-5-5 or 6-6-5-5-5-5 |
| Adobe | p8e- + 32 alnum |
| age | AGE-SECRET-KEY-1 + 58 upper-case Bech32 |
| Airtable | pat + 14 alnum + . + 64 hex |
| Alibaba Cloud | LTAI + 20 alnum |
| AWS Bedrock | ABSK + 109 to 269 base64; bedrock-api-key- + 20 or more base64 |
| Clojars | CLOJARS_ + 60 alnum |
| Cloudflare origin CA | v1.0- + 24 hex + - + 146 hex |
| Databricks | dapi + 32 hex, optionally - and a digit |
| Defined Networking | dnkey- + 26 token bytes or = + - + 52 more |
| DigitalOcean | doo_v1_, dop_v1_ or dor_v1_ + 64 hex |
| Discord | discord.com/api/webhooks/ (or discordapp.com, ptb., canary.) + 17 to 20 digit ID + / + 60 to 80 byte token |
| Doppler | dp.pt. + 43 alnum |
| Duffel | duffel_test_ or duffel_live_ + 43 token bytes or = |
| Dynatrace | dt0c01. + 24 alnum + . + 64 alnum |
| EasyPost | EZAK or EZTK + 54 alnum |
| Facebook | EAAM or EAAC + 100 or more alnum; app ID of 15 or 16 digits + \| + 27 to 40 token bytes |
| Flutterwave | FLWSECK_TEST- or FLWSECK- + 32 of 0-9 and a-h + -X; FLWSECK_TEST- + 12 of them |
| Fly.io | fo1_ + 43 token bytes; fm1a_, fm1r_ or fm2_ + 100 or more base64 |
| Frame.io | fio-u- + 64 token bytes or = |
| GitLab | glptt- + 40 hex; the token prefixes in KindServiceToken |
| Google | ya29. + 20 or more token bytes (OAuth access token); 1//0 + 20 or more token bytes (refresh token) |
| Grafana | glc_ + 32 to 400 base64; glsa_ + 32 alnum + _ + 8 hex; eyJrIjoi + 70 to 400 alnum |
| Harness | pat. or sat. + 22 token bytes + . + 24 alnum + . + 20 alnum |
| HashiCorp Terraform | 14 alnum + .atlasv1. + 60 to 70 token bytes or = |
| HashiCorp Vault | hvs. + 90 to 300 token bytes; hvb. + 138 to 300 |
| Heroku | HRKU-AA + 58 token bytes |
| Hugging Face | hf_ or api_org_ + 34 letters |
| Infracost | ico- + 32 alnum |
| JFrog Artifactory | AKCp + 69 alnum; cmVmd + 59 alnum |
| Linear | lin_api_ + 40 alnum |
| Mailchimp | 32 hex + -us + 2 digits |
| Mailgun | key- + 32 hex |
| MaxMind | 6 alnum + _ + 29 alnum + _mmk |
| Microsoft Entra | 3 of alnum, _, ~ or dot + a digit + Q~ + 31 to 34 of those or - |
| Microsoft Teams | https://*.webhook.office.com/webhookb2/ path with /IncomingWebhook/ |
| New Relic | NRAK- + 27 alnum; NRJS- + 19 hex; NRII- + 32 token bytes |
| Notion | ntn_ + 46 alnum |
| Octopus Deploy | API- + 26 upper-case alnum |
| OpenAI | sk-admin- + 16 or more token bytes; sk- + 48 alnum |
| OpenShift | sha256~ + 43 token bytes |
| Perplexity | pplx- + 48 alnum |
| Plaid | access-sandbox-, access-development- or access-production- + a lower-case UUID |
| PlanetScale | pscale_tkn_, pscale_oauth_ or pscale_pw_ + 32 to 64 token bytes, = or dots |
| Postman | PMAK- + 24 hex + - + 34 hex |
| Prefect | pnu_ + 36 alnum |
| Pulumi | pul- + 40 hex |
| ReadMe | rdme_ + 70 lower-case alnum |
| RubyGems | rubygems_ + 48 hex |
| Scalingo | tk-us- + 48 token bytes |
| Brevo | xkeysib- + 64 hex + - + 16 alnum |
| Sentry | sntryu_ + 64 hex; sntrys_eyJ + 20+ base64 or _; hosted DSN https://KEY@o*.ingest*.sentry.io/ with a 32 hex KEY |
| SettleMint | sm_aat_, sm_pat_ or sm_sat_ + 16 alnum |
| Shippo | shippo_live_ or shippo_test_ + 40 hex of either case |
| Shopify | shpat_, shpca_, shppa_ or shpss_ + 32 hex of either case |
| Slack | xapp- + digit + - + alnum + - + digits + - + 32 or more alnum; workflow and trigger webhook URLs |
| SonarQube | squ_, sqp_ or sqa_ + 40 alnum |
| Sourcegraph | sgp_ + 16 hex + _ + 40 hex, sgp_local_ + 40 hex or sgp_ + 40 hex |
| Telegram | bot ID of 5 to 16 digits + : + A + 34 token bytes, also after /bot in Bot API URLs |
| Twilio | SK + 32 hex of either case |
| Typeform | tfp_ + 59 token bytes, = or dots |
| Yandex Cloud | AQVN + 35 to 38 token bytes |
| 42 | s-s4t2ud- or s-s4t2af- + 64 hex |

Run `python3 scripts/gitleaks_oracle.py --cache DIR` with DIR outside the repository to measure the default scanner against the true-positive lines that gitleaks validates while generating its rules: each rule's sample secret placed in 26 key-and-syntax forms, plus the secret alone after a non-credential word. The examples resemble real credentials, so they stay in the cache. On gitleaks v8.30.0 the default scanner masks:

| Input | Examples masked | Rules fully masked |
|---|---|---|
| Generated lines with keys and syntax | 5930/6368 (93.1%) | 118/215 |
| Bare secrets without a key | 321/539 (59.6%) | 110/215 |

Version 0.11.0 masked 4349 lines covering 27 rules and 105 bare secrets covering 18 rules on the same examples. The remaining bare secrets are mostly rules whose secret is a plain hexadecimal or alphanumeric string identified only by a nearby provider name such as `discord` or `heroku`; embargo masks those values when the key itself names a credential. A bare curl user:password example also counts as missed because embargo keeps the username visible, as it does in URL userinfo. Of the 438 lines it still misses, 296 are base64-encoded JWTs without a key and 105 are Java `System.setProperty("NAME_TOKEN", "value")` calls, which are source code rather than log output.

The general minimum suffix length is a conservative detector heuristic, not a vendor specification. Prefix matching does not validate token checksums or revocation. Formats can evolve; public examples are the evidence, and local synthetic tests never use real keys.

[KindHighEntropy](https://pkg.go.dev/github.com/nao1215/embargo@main#KindHighEntropy) defines the opt-in statistical heuristic and its exclusions. A public random ID without its label is indistinguishable from a secret with the same character distribution; see the measured false positives in [accuracy](accuracy.md).

Scanner, slog, adapters and embargotest keep the existing threshold 0 contract. Slog and adapters receive an explicit Scanner, so changing its threshold behind the caller's back would discard their chosen findings. embargotest keeps low-confidence checks to favor finding forgotten values. Users who want fewer ambiguous candidates can pass `WithMinConfidence(0.5)` explicitly, accepting the documented entropy recall loss. Confidence is not probability, and a clean result proves only the tested canary, detector set and observed paths.

Error values are checked using their full Error text after wrapping or joining. A MaskError wrapper was deliberately not added: an Unwrap method would let Sentry or another chain-walking consumer recover the original unsanitized message, while removing Unwrap would break errors.Is/errors.As. At an external text-only boundary, use `embargo.Mask(err.Error(), scanner.ScanString(err.Error()))` and retain the original error for local identity checks. For SDK events, inspect or sanitize the complete serialized event, including each exception, resource and context.

[Support maintenance](https://github.com/sponsors/nao1215).
