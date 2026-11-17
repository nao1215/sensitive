# embargo

embargo keeps secrets and personal data out of what a Go program writes: logs, error reports, HTTP access logs and traces. The root module uses only the standard library. The library exists for four jobs, using the same boundaries described in the README:

- Keep a known secret from ever printing: Secret emits the reserved marker through fmt, JSON, XML, templates and loggers; Reveal is explicit.
- Log existing structs, errors and JSON: MaskJSON, the slog handler and SDK adapters preserve keys, types and nesting while masking sensitive content.
- Catch secrets nobody declared: value detectors check token grammar, URL passwords, cards, bank numbers, email, IPs and other supported values.
- Prove in CI that no secret reaches output: embargotest checks synthetic canaries in stdout, logs, HTTP responses and child processes.

## Architecture

The root package owns immutable scanner policy, public findings, masking, Secret/Input, the validated JSON walk, event scalar policy, slog and HTTP. internal/detect owns detector grammar and validation. internal/ascii owns byte primitives; internal/saferecord owns fixed diagnostics and request budgets; internal/output owns masked JSON framing. embargotest owns capture, canaries and expectations. cmd/embargo-audit owns local log inspection. Each of the six adapters is an independent module with its own SDK dependencies. Runtime code never imports embargotest; root never imports internal/output or an adapter.

The production package inventory below is checked against go list in the root and every adapter by scripts/check_policies.py. Tool, integration and fixture packages live in the separate tests module.

<!-- packages:start -->
- `github.com/nao1215/embargo`
- `github.com/nao1215/embargo/adapters/grpc`
- `github.com/nao1215/embargo/adapters/logrus`
- `github.com/nao1215/embargo/adapters/otel`
- `github.com/nao1215/embargo/adapters/sentry`
- `github.com/nao1215/embargo/adapters/zap`
- `github.com/nao1215/embargo/adapters/zerolog`
- `github.com/nao1215/embargo/cmd/embargo-audit`
- `github.com/nao1215/embargo/embargotest`
- `github.com/nao1215/embargo/internal/ascii`
- `github.com/nao1215/embargo/internal/detect`
- `github.com/nao1215/embargo/internal/output`
- `github.com/nao1215/embargo/internal/saferecord`
<!-- packages:end -->

### Shared boundary contracts

A finding is a half-open byte span [Start, End) in the caller's original input, with kind and confidence. It never uses rune indexes. Internal detector findings contain only those four facts; validation helpers own checksum, issuer and BIN decisions. The root translates internal names to public kinds, validates findings, applies the inclusive confidence threshold and sorts stably. Custom detectors receive original bytes.

A normalized view carries an optional boundary map: nil means identity, and every non-nil map includes the exclusive end sentinel. ComposePositions in internal/detect/fullwidth.go composes view maps in place. Root percent decoding runs once and preserves literal plus and malformed escapes. Unicode token-separator normalization, numeric full-width normalization and credential quote decoding keep their distinct encoding rules but use original byte offsets. Credential.ScanViews keeps raw URL/DSN delimiter ownership while also checking normalized assignments. Quote decoding remains eager and bounded to four layers.

Credential rendering is split into key normalization and matching policy (credential_key.go), key parsing and assignment/Go fmt grammar (credential_render.go), Authorization (credential_authorization.go), URL/DSN and formatted URL values (credential_url.go), and escape views (credential_escape.go). credential.go coordinates recognition and deduplication. credentialQuoteEnd and credentialContainerEnd own quote escaping and nested container ends for rendered credentials and Authorization. The rendering parser owns enclosing delimiters, while findings cover the enclosed values; a less-escaped accepted span prevents a later decode from reinterpreting its interior.

JSON grammar is separate from Go fmt grammar. json.Valid establishes the grammar before jsonWalker preserves object order, duplicate keys and exact numeric lexemes. JSON strings use encoding/json decoding; Go fmt accepts typed containers, conversions, backticks and truncated renderings that are not JSON. event.go owns cumulative scalar budgets, key context and joined-key crossing; integer.go owns bounded exact integer representations without floating-point rounding. Slog and HTTP use the same event policy.

PEMHeader and PEMFooter in internal/detect/private_key_pem.go exclusively own PEM/PGP labels, frames and incomplete blocks. Root stream.go owns buffers, line numbers and continuation state, using the same normalized input and offset mapping as whole-input scanning. It does not parse another literal-only frame grammar.

Boundary families have deliberate differences. ASCII word boundaries treat underscore as a separator; identifier bytes add underscore, and token bytes add underscore and hyphen. Their owners and users are:

| Rule | Owner | Users and distinction |
|---|---|---|
| ASCII word | boundary.go: isAlphaNum, isWordBoundary | Keyword labels, AWS, ABA and Bech32 candidate bytes |
| Identifier byte | boundary.go: isIdentifierByte | PAN, BTC, ETH, phone, My Number, IP, country IDs, service/payment leading boundaries and GitHub bodies |
| Token byte | boundary.go: isTokenByte | Google, service/payment, entropy, developer/JWT and email local-part candidates |
| Encoded separator | boundary.go: encodedSeparatorBefore | Detector leading boundaries recognize only the documented percent-encoded separators |
| Label | label.go | Numeric/business confidence and labeled IP context; field words remain distinct from token bytes |
| Numeric log context | log_context.go | PAN/phone fragments and SWIFT/ABA register, user, hardware, exception and sequence exclusions |
| URL delimiter | credential_url.go: urlDelimiter | URL/DSN credentials and the email SCP-remote exclusion share this delimiter set |
| Hex digit | internal/ascii: DecodeHex; boundary.go: isHexDigit | Percent escapes, Ethereum, IPv6 and numeric log context share one ASCII alphabet |

Bech32 candidates use ASCII alphanumeric bytes; case consistency and checksum validation remain separate. IP sentence punctuation remains in ipaddr.go; ARN account context remains in mynumber.go. These domain rules do not become generic delimiters. Named boundaries must keep existing detection and masking semantics when code moves.

## Development commands

- make test runs root tests and writes cover.out and cover.html; make lint runs the configured linters.
- make clean removes generated build artifacts; make tools installs development tools; make benchmark runs benchmark tests.
- make race runs root, tests and the six adapters in sequence; make properties runs integration and contract tests.
- python3 scripts/check_policies.py checks repository policy, package documentation, test layout and function growth.
- python3 scripts/diff_coverage.py --base origin/main checks changed statements.
- python3 scripts/quality_gate.py accuracy checks accuracy, critical recall and residual exposure.
- python3 scripts/quality_gate.py false-positives --cache CACHE checks checksum-pinned real logs.
- python3 scripts/detection_changes.py --base origin/main --cache CACHE checks the findings snapshot.
- python3 scripts/ci_benchmark.py --base origin/main --head HEAD runs the paired benchmark gate.
- make mutation runs full per-package mutation checks and reruns timed-out mutants alone; make mutation-diff BASE=origin/main mutates only changed lines while working; make fuzz discovers and exercises root fuzz targets.

Run heavy jobs one at a time with GOMAXPROCS at most 4. Use existing commands and inspect failed evidence before repeating a job. Do not weaken a gate to accommodate a refactor. Keep benchmark evidence on the same machine with alternating revision order.

## Coding and tests

Write code comments and documentation in English. Keep Markdown paragraphs on one line and avoid bold and emoji. Use English Conventional Commits without agent trailers. Keep CI timing tables in PR bodies only. Do not put development round labels, finding IDs or this repository's PR numbers and commit hashes in tracked files. Do not add pseudo-versions or root dependencies.

Follow Effective Go, use explicit state instead of globals, use errors.Is/errors.As for typed error comparisons, and check returned errors. Every library package has a doc.go overview; exported functions, variables and fields have Go documentation comments explaining behavior and limits. Public APIs have runnable examples, detector comments describe their recognition and validation rules, and implementation comments explain decisions. Check for duplicate code after changes. Keep architecture dependencies, strict lint rules and constructor contracts intact. Preserve hint-based filtering before expensive detector work and avoid regular expressions when a bounded parser can express the grammar. Do not add a public package for an internal refactor.

Use synthetic sensitive values, published test card numbers and example domains. Tests describe observable inputs and outputs; property, differential, boundary and fuzz tests preserve parser contracts. A production bug fix starts with a failing reproduction. A refactor starts with unchanged-input equivalence evidence. Test files have one source counterpart: source.go permits source_test.go, with example_test.go, fuzz_test.go and benchmark_test.go also permitted per package. The tests module has the canonical subjects listed by check_policies.py. Split a source's tests along with its responsibilities, preserving or increasing the total number of test functions.

Keep the test pyramid and the test-first approach described by Takuto Wada. Prefer readable cases with explicit inputs and expected outputs over deduplicating away their intent; t.Run names describe that relationship. Use t.Parallel when tests are independent. Ensure make test and make lint succeed, and inspect octocov coverage after make test. CI retains Linux, macOS and Windows coverage of supported behavior.

The total coverage gate is 97%; diff coverage, package mutation score and mutation coverage floors, accuracy, critical recall and exposure floors, scaling limits, real-log ceilings and the paired benchmark regression gate are all enforced. Their executable values live in .octocov.yml, scripts/diff_coverage.py, doc/mutation-baseline.json, doc/quality-gates.json and the corresponding gate scripts. Continuous fuzzing, platform/race checks, API goldens, dependency checks, security scans and formal/oracle replay remain enabled.

The function growth gate records statements, cyclomatic complexity and lines in doc/function-baseline.json. It watches the largest ten functions by statements and CC, previously recorded functions and the main scanner/rendering/hook/capture entry points. Statements exclude blocks, case/communication clauses and empty statements; CC is one plus branches, loops, non-default cases and logical operators, including closures. Growth in statements or CC, a new largest function or removal of a recorded function requires a reviewed baseline update in the same PR using go -C tests run ./cmd/functionmetrics --write. Split functions by responsibility, not to evade the baseline; line counts are reported for review.

README content above Quick start is maintained independently. Compare it with current origin/main before each PR and preserve current upstream edits. Keep sponsor links at https://github.com/sponsors/nao1215 in project documentation and explain contribution workflows for new contributors.

## Release order

Refactors with no observable change do not require releases. When a release is needed, first merge and tag the root, verify its published module through the public proxy with checksum verification, then update adapter root requirements and test without local replacements. Merge and tag each adapter only after the root is available. Update installation examples and integration-module adapter versions after their tags are published. API signatures and behavioral detection changes are reviewed separately; intentional detection changes require the existing release-note and findings snapshot policy. Never release from PR verification, force-push, or modify unrelated repositories or other contributors' PRs and issues.
