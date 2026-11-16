# Supported detectors

The [Kind godoc](https://pkg.go.dev/github.com/nao1215/embargo@main#Kind) defines each matching rule, validation step, emitted confidence and default selection. The [README table](../README.md#find-and-mask-sensitive-text) is generated from those comments. Use this page to interpret findings and choose a threshold; format acceptance does not establish account ownership, identity issuance or successful authentication.

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

Numeric parsers reject decimal tails and some hostname fragments so operational log fields do not become isolated identifiers. Boundaries differ by family: contextual digit searches can find a digit run beside letters, while country parsers exclude adjacent ASCII identifier characters. [Scan](https://pkg.go.dev/github.com/nao1215/embargo@main#Scanner.Scan) documents decoding and byte offsets; [Kind](https://pkg.go.dev/github.com/nao1215/embargo@main#Kind) documents normalization and business-label scope. The [adversarial encoding regressions](testing.md#adversarial-budgets) retain examples of unsupported disguises.

[Credential grammar and provider sources](credentials.md) explain the evidence behind secret detection. Prefixes alone do not check revocation, and the generic credential parser cannot evaluate programming-language expressions or reconstruct values assembled at runtime. The [real-log analysis](real-logs.md) records observed false positives without claiming recall for unknown production secrets.

## Updating detector documentation

Edit the individual constant comment in finding.go, then run `go -C tests run ./cmd/detectordocs`. Each comment separates matching from validation with its first semicolon and ends with the NewScanner default in parentheses. The generator uses go/ast, takes the first validation sentence and shortens cells at word boundaries to the prose checker's 120-character budget; each Kind links to its full godoc. There is no second rule list to edit.

`go -C tests run ./cmd/detectordocs --check` rejects stale output. `go -C tests test ./cmd/detectordocs` checks all constants, validation clauses, README membership, exact regeneration, observed confidence tiers and default detection through `NewScanner()`. Both commands run in CI; a new kind needs representative inputs for each score before its documentation can pass.

[Support maintenance](https://github.com/sponsors/nao1215).
