# Where a logging policy stops

Each case is a small Go program that writes a planted secret through one application path: a struct field added after its masking rules were written, an error from an HTTP client, a database DSN, a dumped header and eight others. The [runnable cases](../tests/adoption_cases_test.go) apply four approaches to the same output and record, per approach, whether the secret was masked, caught by the output test, or missed.

## Measured output

Every column runs a masker, then the same embargotest Recorder on its actual output. Masked means every declared sensitive fragment disappeared; detected means a fragment survived masking and the recorder rejected the output; missed means a fragment survived both. Detection is an output-test result, not a masking feature of masq or the manual policies. Full synthetic secrets are planted as canaries. A plain unprotected control must expose the fixture; separate positive controls prove each declared policy actually masks. Every path must retain an order ID and a completion message.

<!-- adoption-cases:start -->
| Application path | masq tags | Manual redact | Key denylist | embargo |
|---|---|---|---|---|
| added struct field | detected | detected | detected | masked |
| client error | detected | detected | detected | masked |
| HTTP query | detected | masked | detected | masked |
| wrapped error | detected | masked | detected | masked |
| DSN password | detected | detected | detected | masked |
| header dump | detected | detected | detected | masked |
| unwrapped logger | detected | detected | detected | detected |
| card last four | missed | missed | missed | missed |
| truncated card | missed | missed | missed | missed |
| base64 token | detected | detected | detected | detected |
| hex token | detected | detected | detected | detected |
| split token lines | missed | missed | missed | missed |
<!-- adoption-cases:end -->

masq v0.2.3 is pinned by tests/go.mod. The tag column uses its documented WithTag("secret"); the denylist column uses its recursive field-name policy for Password, password, token and authorization. The manual ReplaceAttr function replaces 13–19 digit cards and password/token assignments in strings and errors. The embargo column uses NewSlogHandler with NewScanner defaults. These explicit policies receive identical events and no oracle of secret values. Teams can expand any policy; these results do not rank all possible configurations. The broader [comparison](comparison.md) also measures masq with regexes and partial replacement options.

## What the cases leave exposed

The unwrapped logger writes to the captured sink through log.New, bypassing every slog handler. The recorder catches the full token. Production masking still requires wrapping or removing that output path; a test failure alone does not sanitize deployed logs.

Last-four and eight-digit card fragments are outside PAN recognition. The split token crosses two JSON records, so neither a full token detector nor default whole-canary matching reconstructs it. The opt-in WithCanaryFragments(16) check added afterward catches its long raw pieces; the table above retains the default policy. Base64 and hex tokens are outside default detector decoding, but whole-value canary representations catch these two fixtures independently. See [what each output check proves](testing-output.md). Hashes, arbitrary transforms and unobserved output need explicit tests and policy decisions.

Last-four display may be intentional. Here it is deliberately classified as exposure to show the boundary; a team's own policy must decide whether to permit it. Keeping useful order IDs and completion messages is also an assertion, because deleting diagnostic context is an operational failure.

## Try it on an existing handler

The existing application still calls logger.Info and keeps its data types. Replace its handler construction with `slog.New(embargo.NewSlogHandler(existingHandler, embargo.NewScanner()))`, connect the test sink to `recorder.Writer("logs")`, plant a fake secret through the normal application input and assert useful output before Check. No changes to third-party client code are needed. The [existing-masker integration](testing-output.md#keep-an-existing-masker-and-check-the-real-application-output) also keeps masq and adds only the output check. This small in-repository HTTP checkout fixture demonstrates wiring cost, not a migration estimate for a production service; inventory alternate loggers, flush points and outputs outside the selected sink.

Run `python3 scripts/case_docs.py --check` to execute the cases and reject a stale table; omit --check to regenerate it. The tests module runs them on all supported CI platforms.

[Support maintenance](https://github.com/sponsors/nao1215).
